import os
import threading
from collections import defaultdict

import psutil
import time
from datetime import datetime
import csv
import sys
import traceback
import subprocess


def handle_crash(exc_type, exc_value, exc_tb):
    print("\n" + "=" * 55)
    print("CRASH — read the error below:")
    print("=" * 55)
    traceback.print_exception(exc_type, exc_value, exc_tb)
    print("=" * 55)
    input("\nPress Enter to close...")  # keeps window open


sys.excepthook = handle_crash

CRYPTO_API_PATTERNS = [

    {
        "api_name": "CryptAcquireContext",
        "score": 70,
        "stage": "CRYPTO_SETUP",
        "reason": "Opening Windows cryptographic provider - encryption engine being initialized",
        "detail": "This is the FIRST call any encryption operation must make. "
                  "Normal apps rarely call this outside of TLS/certificate operations.",
        "cite": "RansoGuard (Cen et al., 2025); Arabo et al. (2020)"
    },
    {
        "api_name": "CryptGenKey",
        "score": 80,
        "stage": "CRYPTO_SETUP",
        "reason": "Generating new encryption key - ransomware creating AES/RSA key",
        "detail": "Ransomware generates a unique AES key per victim. "
                  "CryptGenKey + CryptAcquireContext together = near certain ransomware.",
        "cite": "RansoGuard (Cen et al., 2025)"
    },
    {
        "api_name": "CryptImportKey",
        "score": 80,
        "stage": "CRYPTO_SETUP",
        "reason": "Importing encryption key from C2 server - key received from attacker",
        "detail": "Some ransomware gets the key FROM the C2 server rather than generating it. "
                  "Both CryptGenKey and CryptImportKey indicate imminent encryption.",
        "cite": "RansoGuard (Cen et al., 2025)"
    },
    {
        "api_name": "CryptEncrypt",
        "score": 100,  # INSTANT KILL - encryption already starting!
        "stage": "ENCRYPTION_STARTED",
        "reason": "CryptEncrypt called - file encryption is ACTIVELY HAPPENING NOW",
        "detail": "If we see this, encryption has started. Trigger immediate process kill.",
        "cite": "Arabo et al. (2020); Zhang et al. (2024)"
    },
    {
        "api_name": "BCryptEncrypt",  # Modern API used by newer ransomware
        "score": 100,
        "stage": "ENCRYPTION_STARTED",
        "reason": "BCryptEncrypt called - modern crypto API, encryption is happening",
        "detail": "Newer ransomware families use BCrypt (newer than CryptEncrypt). "
                  "WannaCry, REvil, LockBit use this API.",
        "cite": "Zhang et al. (2024)"
    },

    {
        "api_name": "advapi32.dll",  # Windows crypto API library
        "score": 30,
        "stage": "CRYPTO_LIBRARY_LOAD",
        "reason": "Crypto library (advapi32.dll) loaded by suspicious process",
        "detail": "advapi32.dll contains CryptAcquireContext, CryptGenKey, etc. "
                  "Loading this DLL is a prerequisite for encryption. "
                  "Low score alone (30) but combined with other signals = very suspicious.",
        "cite": "Arabo et al. (2020) - DLL call analysis"
    },
    {
        "api_name": "bcrypt.dll",  # Modern Windows crypto library
        "score": 30,
        "stage": "CRYPTO_LIBRARY_LOAD",
        "reason": "Modern crypto library (bcrypt.dll) loaded",
        "detail": "bcrypt.dll is used by newer ransomware for faster AES-256 encryption.",
        "cite": "Zhang et al. (2024)"
    },

    {
        "api_name": "FindFirstFileW",
        "score": 20,
        "stage": "FILE_ENUMERATION",
        "reason": "Mass file enumeration starting - building list of files to encrypt",
        "detail": "FindFirstFileW is how programs iterate through directories. "
                  "Benign apps do this sparingly. Ransomware does it across ALL user dirs "
                  "very rapidly. Combined with crypto API = almost certainly ransomware.",
        "cite": "Arabo et al. (2020); RansoGuard (Cen et al., 2025)"
    },
    {
        "api_name": "GetLogicalDrives",
        "score": 30,
        "stage": "FILE_ENUMERATION",
        "reason": "Process mapping ALL drives including network shares",
        "detail": "GetLogicalDrives returns a list of ALL drive letters. "
                  "Ransomware calls this to find network shares to encrypt too. "
                  "Very few legitimate apps need to enumerate ALL drives.",
        "cite": "RansoGuard (Cen et al., 2025)"
    },
]
WHITELISTED_PROCESSES = {
    # Windows system processes that use crypto legitimately:
    "lsass.exe",  # Windows authentication
    "svchost.exe",  # Windows services (many use crypto)
    "explorer.exe",  # Windows Explorer (file copy uses crypto)
    "chrome.exe",  # Browser (HTTPS uses crypto)
    "firefox.exe",  # Browser
    "msedge.exe",  # Edge browser
    "outlook.exe",  # Email (uses crypto for S/MIME)
    "onedrive.exe",  # Cloud sync (encrypts for transfer)
    "teams.exe",  # Teams (encrypted communications)
    "zoom.exe",  # Video calls
    "python.exe",  # Our own detector! Don't flag ourselves
    "pythonw.exe",

    # Security software (uses crypto heavily):
    "mbam.exe",  # Malwarebytes
    "avast.exe",
    "avgnt.exe",
    "mcshield.exe",
    "msseces.exe",  # Microsoft Security Essentials
    "msmpeng.exe",  # Windows Defender
}

HIGH_RISK_PROCESSES = {
    "cmd.exe",  # Command prompt
    "powershell.exe",  # PowerShell (ransomware loves this)
    "wscript.exe",  # Windows Script Host
    "cscript.exe",  # Command-line Script Host
    "mshta.exe",  # HTML Application Host
    "rundll32.exe",  # DLL runner (often abused)
    "regsvr32.exe",  # Registry server (often abused)
    "msiexec.exe",  # Installer (can be abused)
}
SIGNATURE_CACHE = {}  # {exe_path: True/False}

class APIMonitor:
    def __init__(self, threat_callback, log_callback, procmon_csv_path=None):
        self.threat_callback = threat_callback
        self.log_callback = log_callback
        self.procmon_csv_path = procmon_csv_path
        self.running = False
        self.threads = []
        self.detections = []
        self.flagged_per_process = defaultdict(lambda: defaultdict(int))  # dublication tracker
        # defaultdict(int)==> dictionary where missing key automaticaly returns 0 rather than raising error
        # defaultdict(lamda : defaultdict(int))==> a dictionary where missing keys automatically return new  obj
        # Track suspicious processes: {pid: total_score}
        self.suspicious_pids = defaultdict(int)

    def _is_whitelisted(self, process_name):
        return process_name.lower() in WHITELISTED_PROCESSES

    def _get_risk_multiplier(self, process_name):
        return 2.0 if process_name.lower() in HIGH_RISK_PROCESSES else 1.0

    def _process_api_hit(self, pid, process_name, api_name, pattern,
                         source="procmon"):
        if self._is_whitelisted(process_name):
            return

        # Deduplicate: only fire the first 3 times per API per processzzzzzzz
        self.flagged_per_process[pid][api_name] += 1
        occurrence = self.flagged_per_process[pid][api_name]
        if occurrence > 3:
            return  # Already flagged this process for this API enough

        # Calculate score (with risk multiplier for high-risk processes)
        base_score = pattern["score"]
        multiplier = self._get_risk_multiplier(process_name)
        final_score = int(base_score * multiplier)

        self.suspicious_pids[pid] += final_score

        timestamp = datetime.now().isoformat()
        detection = {
            "type": "API_CALL_DETECTED",
            "timestamp": timestamp,
            "pid": pid,
            "process": process_name,
            "api": api_name,
            "score": final_score,
            "base_score": base_score,
            "multiplier": f"{multiplier}x ({'HIGH-RISK process' if multiplier > 1 else 'normal process'})",
            "stage": pattern["stage"],
            "reason": pattern["reason"],
            "occurrence": f"{occurrence}/3",
            "total_pid_score": self.suspicious_pids[pid],
            "citation": pattern["cite"],
            "source": source
        }
        self.detections.append(detection)

        print(f"API CALL DETECTED! Stage: {pattern['stage']}")
        print(f" Process:      {process_name} (PID: {pid})")
        print(f"API Called:   {api_name}")
        print(f"Reason:       {pattern['reason']}")
        print(f"Score:        +{final_score} (base {base_score} × {multiplier}x)")
        print(f"Total PID:    {self.suspicious_pids[pid]} points")
        print(f"Time:         {timestamp}")
        print(f"Citation:     {pattern['cite']}")
        if occurrence > 1:
            print(f"Occurrence:   {occurrence}/3 (same API, same process)")

        self.threat_callback(
            score=final_score,
            reason=f"API: {process_name} called {api_name} ({pattern['stage']})",
            details=detection
        )
        self.log_callback("API_CALL_DETECTED", detection)

    def _watch_process_dlls(self):
        known_pids = set()  # PIDs we've already checked
        print("Process DLL tracker active (no ProcMon required)")
        while self.running:
            time.sleep(0.5)  # Check every 500ms

            try:
                current_pids = set(p.pid for p in psutil.process_iter())
                new_pids = current_pids - known_pids
                known_pids = current_pids

                for pid in new_pids:
                    self._check_new_process(pid)

            except Exception:
                pass


    def is_trusted_signature(self, exe_path):
        if not exe_path or not os.path.exists(exe_path):
            return False

        # check cache first — avoid calling PowerShell twice for same exe
        if exe_path in SIGNATURE_CACHE:
            return SIGNATURE_CACHE[exe_path]

        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 f"(Get-AuthenticodeSignature '{exe_path}').Status"],
                capture_output=True,
                text=True,
                timeout=3
            )
            status = result.stdout.strip()
            is_valid = status == "Valid"
            SIGNATURE_CACHE[exe_path] = is_valid  # save result
            return is_valid

        except Exception:
            SIGNATURE_CACHE[exe_path] = False
            return False


    def _check_new_process(self, pid):
        """
        Check a newly-started process for suspicious behaviour.
        Called for EVERY new process that appears on the system.
        """
        try:
            proc = psutil.Process(pid)
            name = proc.name()

            # Skip whitelisted processes early
            if self._is_whitelisted(name):
                return

            try:
                exe_path = proc.exe()
                if self.is_trusted_signature(exe_path):
                    print(f"  [SIGNED] {name} — trusted publisher, skipping")
                    return  # ← signed = safe, stop immediately
            except Exception:
                pass  # can't get exe path — continue investigation


            # Get list of DLLs loaded by this process:
            try:
                dlls = [m.path.lower() for m in proc.memory_maps()]
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                return

            # Check for crypto DLLs:
            crypto_dlls_found = []
            for dll_path in dlls:
                dll_name = os.path.basename(dll_path)
                for pattern in CRYPTO_API_PATTERNS:
                    if pattern["api_name"].lower() == dll_name:
                        crypto_dlls_found.append((dll_name, pattern))

            # If any crypto DLL found, investigate further:
            if crypto_dlls_found:
                self._investigate_process(proc, name, pid, crypto_dlls_found)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass  # Process died before we could check - normal




    def _investigate_process(self, proc, name, pid, crypto_dlls):
        """
        - Crypto DLL + command line contains suspicious paths
        - Crypto DLL + rapid file access (many open file handles)
        - Crypto DLL + no recognisable executable name
        """
        try:
            # Check the process command line for suspiciousness:
            cmdline = " ".join(proc.cmdline()).lower()

            # Score factors:
            investigation_score = 0
            reasons = []




            # Factor 1: Crypto DLLs loaded
            for dll_name, pattern in crypto_dlls:
                # investigation_score += pattern["score"]
                reasons.append(f"Loaded {dll_name}")
                self._process_api_hit(
                    pid=pid,
                    process_name=name,
                    api_name=dll_name,
                    pattern=pattern,
                    source="dll_tracking"
                )

            # Factor 2: Suspicious parent process
            try:
                parent = psutil.Process(proc.ppid())
                parent_name = parent.name().lower()
                if parent_name in ("winword.exe", "excel.exe", "outlook.exe",
                                   "chrome.exe", "firefox.exe"):
                    # Child of Office/browser = could be macro malware!
                    investigation_score += 40
                    reasons.append(
                        f"Spawned by {parent.name()} (macro/browser exploit?)"
                    )
            except Exception:
                pass

            # Factor 3: Process running from temp/unusual location
            try:
                exe_path = proc.exe().lower()
                suspicious_paths = ["\\temp\\", "\\appdata\\", "\\downloads\\",
                                    "\\desktop\\", "\\public\\"]
                for sp in suspicious_paths:
                    if sp in exe_path:
                        investigation_score += 30
                        reasons.append(f"Running from suspicious path: {exe_path}")
                        break
            except Exception:
                pass

            # Factor 4: Many open file handles (actively reading files)
            try:
                open_files = len(proc.open_files())
                if open_files > 20:
                    investigation_score += 20
                    reasons.append(f"Has {open_files} open file handles")
            except Exception:
                pass

            if reasons:
                print(f"\n Investigated PID {pid} ({name}):")
                for r in reasons:
                    print(f"     → {r}")
                print(f"     Total investigation score: {investigation_score}")
            if investigation_score > 0:
                self.threat_callback(
                    score=investigation_score,
                    reason=f"INVESTIGATION: {name} suspicious behaviour ({', '.join(reasons)})",
                    details={
                        "type": "INVESTIGATION_SCORE",
                        "pid": pid,
                        "process": name,
                        "investigation_score": investigation_score,
                        "reasons": reasons,
                        "stage": "PRE-ENCRYPTION",
                        "timestamp": datetime.now().isoformat()
                    })
                self.log_callback("INVESTIGATION_SCORE", {
                    "pid": pid,
                    "process": name,
                    "score": investigation_score,
                    "reasons": reasons
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def _monitor_combined_scores(self):
        """
        Example:
          CryptAcquireContext (+30) + CryptGenKey (+50) +
          FindFirstFileW (+20) + advapi32.dll load (+30) = 130 points
          → That process is almost certainly ransomware!
        """
        while self.running:
            time.sleep(1)

            for pid, total_score in list(self.suspicious_pids.items()):
                if total_score >= 150:
                    # This process has accumulated huge API evidence
                    try:
                        proc = psutil.Process(pid)
                        name = proc.name()
                        if not self._is_whitelisted(name):
                            self._fire_combined_alert(pid, name, total_score)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

    def _fire_combined_alert(self, pid, process_name, combined_score):

        # Only fire once per process (remove from tracking after alerting)
        del self.suspicious_pids[pid]

        print("COMBINED API EVIDENCE THRESHOLD REACHED!")

        print(f"Process:       {process_name} (PID: {pid})")
        print(f"Total Score:   {combined_score} points (threshold: 150)")
        print(f"APIs flagged:  {list(self.flagged_per_process[pid].keys())}")
        print(f"VERDICT:       HIGH CONFIDENCE RANSOMWARE")
        print(f"Time:          {datetime.now().isoformat()}")

        detection = {
            "type": "COMBINED_API_THRESHOLD",
            "timestamp": datetime.now().isoformat(),
            "pid": pid,
            "process": process_name,
            "combined_score": combined_score,
            "apis_seen": dict(self.flagged_per_process[pid]),
            "stage": "PRE-ENCRYPTION",
            "confidence": "HIGH"
        }
        self.threat_callback(
            score=min(combined_score, 100),  # Cap at 100 extra points
            reason=f"COMBINED API: {process_name} accumulated {combined_score} "
                   f"crypto API points (ransomware pattern confirmed)",
            details=detection
        )
        self.log_callback("COMBINED_API_THRESHOLD", detection)

    def _parse_procmon_line(self, line):
        try:
            parts = next(csv.reader([line]))

            # need at least 5 columns
            if len(parts) < 5:
                return

            # extract the columns we care about
            process_name = parts[1].strip() if len(parts) > 1 else ""
            pid_str = parts[2].strip() if len(parts) > 2 else "0"
            operation = parts[3].strip() if len(parts) > 3 else ""
            path = parts[4].strip() if len(parts) > 4 else ""
            detail = parts[6].strip() if len(parts) > 6 else ""

            # skip the header row
            if process_name in ("Process Name", ""):
                return

            # convert PID to integer
            try:
                pid = int(pid_str)
            except ValueError:
                pid = 0

            # combine all searchable columns into one string
            searchable = f"{operation} {path} {detail}".lower()

            # check each pattern against the searchable string
            for pattern in CRYPTO_API_PATTERNS:
                api_lower = pattern["api_name"].lower()
                if api_lower in searchable:
                    self._process_api_hit(
                        pid=pid,
                        process_name=process_name,
                        api_name=pattern["api_name"],
                        pattern=pattern,
                        source="procmon_csv"
                    )
                    break  # one match per line is enough

        except Exception:
            pass  # malformed line — skip silently

    def _watch_procmon_csv(self):

        # check file exists
        if not self.procmon_csv_path:
            print("  ProcMon CSV: no path provided — skipping")
            return

        if not os.path.exists(self.procmon_csv_path):
            print(f"  ProcMon CSV not found: {self.procmon_csv_path}")
            print(f"  Tip: Start ProcMon → File → Save → CSV format")
            return

        print(f"  ProcMon CSV: reading from {self.procmon_csv_path}")

        # jump to END of file — skip all historical events
        # only process NEW events that happen after detector starts
        with open(self.procmon_csv_path, 'r', errors='ignore') as f:
            f.seek(0, 2)  # 0 = offset, 2 = from end of file
            position = f.tell()  # save current byte position

        print("  Thread 1: ProcMon CSV parser ACTIVE")

        while self.running:
            time.sleep(0.1)  # check every 100ms

            with open(self.procmon_csv_path, 'r', errors='ignore') as f:
                f.seek(position)  # jump to where we last stopped
                new_lines = f.readlines()  # read only NEW lines
                position = f.tell()  # update position for next time

            for line in new_lines:
                self._parse_procmon_line(line)

    def start(self):
        self.running = True
        print("\n Starting API Monitor...")

        # Thread 1 — ProcMon CSV parser
        if self.procmon_csv_path:
            t1 = threading.Thread(
                target=self._watch_procmon_csv,
                daemon=True,
                name="APIMonitor-ProcMon"
            )
            t1.start()
            self.threads.append(t1)
            print("  Thread 1: ProcMon CSV parser ACTIVE")
        else:
            print("  Thread 1: ProcMon CSV parser SKIPPED (no path provided)")

        # Thread 2 — DLL tracker
        t2 = threading.Thread(
            target=self._watch_process_dlls,
            daemon=True,
            name="APIMonitor-DLLTracker"
        )
        t2.start()
        self.threads.append(t2)
        print("  Thread 2: Process DLL tracker ACTIVE")

        # Thread 3 — Combined score monitor
        t3 = threading.Thread(
            target=self._monitor_combined_scores,
            daemon=True,
            name="APIMonitor-ScoreMonitor"
        )
        t3.start()
        self.threads.append(t3)
        print("  Thread 3: Combined score monitor ACTIVE")

        print(f"\n  API Monitor ACTIVE!")
        print(f"  Threads running : {len(self.threads)}")
        print(f"  Patterns watched: {len(CRYPTO_API_PATTERNS)}")

    def stop(self):
        """Stop all monitoring threads."""
        print("\n Stopping API Monitor...")
        self.running = False

    def get_detections(self):
        """Return all API-based detections."""
        return self.detections.copy()

    def get_summary(self):
        """Return summary for reporting."""
        return {
            "total_detections": len(self.detections),
            "patterns_watched": len(CRYPTO_API_PATTERNS),
            "suspicious_pids": dict(self.suspicious_pids),
            "detections": self.detections
        }


if __name__ == "__main__":
    import subprocess

    # ── Real score tracker ─────────────────────────────────────────
    # total_score  = 0
    process_scores = {}
    killed_pids = set()
    all_detections = []


    def real_threat_callback(score, reason, details):
        pid = details.get("pid") if isinstance(details, dict) else None

        if pid is None:
            return
        # add score to this process only
        if pid not in process_scores:
            process_scores[pid] = 0
        process_scores[pid] += score
        current = process_scores[pid]

        print(f"\n [score] PID:{pid} total: {current}/100 | {reason[:60]}")

        if current >= 100:
            process_scores[pid] = 0
            if pid not in killed_pids:
                killed_pids.add(pid)
                print(f"\n pid {pid} hit thershold!")
                print(f"\n terminating pid {pid}!")
                try:
                    result = subprocess.run(
                        ["taskkill", "/F", "/PID", str(pid), "/T"],
                        capture_output=True, text=True
                    )
                    if result.returncode == 0:
                        print(f"!  PID {pid} terminated succefully!")
                    else:
                        print(f"could not kill: {result.stderr.strip()}")
                except Exception as e:
                    print(f"killfailed:{e}")


    def real_log_callback(event_type, details):
        all_detections.append(details)
        # save to file every time so evidence survives even if killed
        import json
        with open("RansomwareDetector/detectors/api_evidence.json", "w") as f:
            json.dump(all_detections, f, indent=2)


    # ── Start monitor ──────────────────────────────────────────────
    print("  API MONITOR - LIVE MODE")
    print("  Waiting for ransomware...")

    monitor = APIMonitor(
        threat_callback=real_threat_callback,
        log_callback=real_log_callback,
        procmon_csv_path=r"/RansomwareDetector/detectors/Logfile.CSV"
    )
    monitor.start()

    try:
        while True:
            time.sleep(1)
            active = {pid: s for pid, s in process_scores.items() if s > 0}
            print(f"[watching..] active_pids={active} detections= {len(all_detections)}")

    except KeyboardInterrupt:
        monitor.stop()
        print(f"\n  Stopped. Total detections: {len(all_detections)}")
        print(f"  Evidence saved to: api_evidence.json")