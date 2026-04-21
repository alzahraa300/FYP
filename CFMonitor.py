import os
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import psutil
import subprocess

signature_cache = {}

def load_decoys(file):
    with open(file, "r", encoding="utf-8") as f:
        data = json.load(f)
    decoys = set()
    watch_dirs = set()

    for path in data:
        #normalize the path for easy comparison on Windows -> watchdog
        full_path = os.path.normcase(os.path.abspath(path))
        decoys.add(full_path)
        watch_dirs.add(os.path.dirname(full_path))

    return decoys, watch_dirs

def log_incident(event_type, src_path, dest_path=None, killed_processes=None):
    if not os.path.exists("incidents"):
        os.makedirs("incidents")

    incident = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"), 
        "event": event_type,
        "src_path": src_path,
        "dest_path": dest_path,
        "killed_processes": killed_processes or []
    }

    file_name = f"incident_{int(time.time())}.json"
    file_path = os.path.join("incidents", file_name)

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(incident, f, indent=4)

def get_process_score(proc):
    score = 0
    reasons = []

    try:
        exe = proc.info["exe"]
        create_time = proc.info["create_time"]

        if exe:
            exe_lower = exe.lower()
            SUSPICIOUS_PATH_KW = {
                "appdata": 3,
                "temp": 3,
                "downloads": 2,
                "users\\public": 3 
            }
            for kw, weight in SUSPICIOUS_PATH_KW.items():
                if kw in exe_lower:
                    score += weight
                    reasons.append(f"running from {kw}")

            if not (
                exe_lower.startswith("c:\\windows") or
                exe_lower.startswith("c:\\program files") or 
                exe_lower.startswith("c:\\program files (x86)")
            ):
                score += 2
                reasons.append("running outside standard folders")

        if create_time and time.time() - create_time < 180:
            score += 2
            reasons.append("recent process")

        try: 
            parent = proc.parent()
            if parent:
                parent_name = parent.name().lower()
                if parent_name in {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"}:
                    score += 2
                    reasons.append(f"launched by {parent_name}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return score, reasons
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return 0, reasons


def is_windows_signed(exe_path):
    if not exe_path:
        return False
    exe_path = os.path.normcase(os.path.abspath(exe_path))

    if exe_path in signature_cache:
        return signature_cache[exe_path]
    
    if not os.path.exists(exe_path):
        signature_cache[exe_path] = False
        return False
    try:
        command = [
            "powershell",
            "-NoProfile",
            "-Command",
            f"$sig = Get-AuthenticodeSignature -LiteralPath '{exe_path}'; "
            f"Write-Output ($sig.Status.ToString() + '|' + $sig.SignerCertificate.Subject)"
        ]

        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        output = result.stdout.strip()

        if not output or "|" not in output:
            signature_cache[exe_path] = False
            return False
        
        status, signer = output.split("|", 1)

        trusted = (status == "Valid" and ("Microsoft Windows" in signer or "Microsoft Corporation" in signer))
        signature_cache[exe_path] = trusted
        return trusted
    except Exception:
        signature_cache[exe_path] = False
        return False

def kill_scored_processes():
    killed = []
    current_pid = os.getpid()

    for proc in psutil.process_iter(["pid", "name", "exe", "create_time"]):
        try:
            pid = proc.info["pid"]
            name = proc.info["name"]
            exe = proc.info["exe"]

            if not name:
                continue
            name_lower = name.lower()
            #don't kill the monitor
            if pid == current_pid:
                continue  
            if is_windows_signed(exe):
                continue

            score, reasons = get_process_score(proc)
            if score >= 5:
                print(f"[KILL] {name} (PID: {pid}) | score = {score}")
                proc.kill()

                killed.append({
                    "pid": pid,
                    "name": name,
                    "exe": exe,
                    "score": score,
                    "reasons": reasons
                })  
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return killed

class DecoyHandler(FileSystemEventHandler):
    #if an event touched a file in that directory check if file a decoy and raise an alert 
    def __init__(self, decoys):
        self.decoys = decoys

    def on_modified(self, event):
        if event.is_directory:
            return 
        path = os.path.normcase(os.path.abspath(event.src_path))
        if path in self.decoys:
            print(f"[DEBUG] Decoy modified: {path}")
            killed = kill_scored_processes()
            if killed:
                print(f"[ALERT] suspicious process found after decoy touchedd: {path}")
                log_incident("modified", path, killed_processes=killed)

    def on_deleted(self, event):
        if event.is_directory:
            return
        path = os.path.normcase(os.path.abspath(event.src_path))
        if path in self.decoys:
            print(f"[DEBUG] Decoy deleted: {path}")
            killed = kill_scored_processes()
            if killed:
                print(f"[ALERT] suspicious process found after decoy touchedd: {path}")
                log_incident("deleted", path, killed_processes=killed)

    def on_moved(self, event):
        if event.is_directory:
            return 
        src_path = os.path.normcase(os.path.abspath(event.src_path))
        dest_path = os.path.normcase(os.path.abspath(event.dest_path))
        if src_path in self.decoys or dest_path in self.decoys:
            print(f"[DEBUG] Decoy moved: {src_path} -> {dest_path}")
            killed = kill_scored_processes()
            if killed:
                print(f"[ALERT] suspicious process found after decoy touchedd: {src_path} -> {dest_path}")
                log_incident("moved", src_path, dest_path, killed_processes=killed)

if __name__ == "__main__":
    decoys, watch_dirs = load_decoys("monitor.json")

    event_handler = DecoyHandler(decoys)
    observer = Observer()
    #monitor directories with decoys only
    for folder in watch_dirs:
        observer.schedule(event_handler, folder, recursive=False)

    observer.start()
    print("Monitoring started :) ")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()

