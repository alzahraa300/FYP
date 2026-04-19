import os
import string
import json
import math
import time
import random
import shutil

MAX_DEPTH = 2
MAX_FOLDERS = 200
MAX_FILES = 200
ALPHA = 0.8
BETA = 0.2

HIGH_VALUE_EXTS = {
    ".doc", ".docx", ".docm",
    ".xls", ".xlsx", ".xlsm",
    ".ppt", ".pptx", ".pptm",
    ".pdf", ".txt", ".csv",
    ".db", ".sql", ".sqlite",
    ".eml", ".msg", ".mbox",
    ".zip", ".rar", ".7z", 
    ".tar", ".gz", ".tgz"
}

LOW_VALUE_EXTS = {
    ".exe", ".dll", ".sys", ".msi", ".ini",
    ".tmp", ".log", ".cache", ".lnk"
}


def get_roots():
    home = os.environ.get("USERPROFILE")  # C:\Users\<username>
    onedrive = os.path.join(home, "OneDrive")

    directories = [os.path.join(home, "Desktop"),
                   os.path.join(home, "Documents"),
                   os.path.join(home, "Downloads"),
                   os.path.join(home, "Pictures"),
                   os.path.join(onedrive, "Desktop"),
                   os.path.join(onedrive, "Documents"),
                   os.path.join(onedrive, "Pictures")]

    #Add non system drives to the list
    drives = []
    for drive in string.ascii_uppercase:
        path = f"{drive}:\\"
        if os.path.exists(path):
            if drive.upper() != "C":
                drives.append(path)

    directories.extend(drives)

    #check if directories exists and non empty
    root = []
    for dir in directories:
        if os.path.isdir(dir):
            try:
                if os.listdir(dir):
                    norm = os.path.normpath(dir)
                    root.append(norm)
            except Exception:
                pass
    return root

def summarize(values):
    if not values:
        return {
            "min": None,
            "max": None,
            "avg": None,
            "median": None
        }
    sorted_values = sorted(values)
    n = len(sorted_values)
    mid = n // 2
    if n%2 == 1:
        med = sorted_values[mid]
    else:
        med = (sorted_values[mid-1] + sorted_values[mid])/2
    
    return {
        "min": sorted_values[0],
        "max": sorted_values[-1],
        "avg": sum(sorted_values)/n,
        "median": med
    }


def choose_templates(files):
    high = []
    low = []
    for f in files:
        if f.get("ext") in HIGH_VALUE_EXTS:
            high.append(f)
            if len(high) == 5: 
                return high
        else:
            low.append(f)

    if not high:
        return low[:5]
    
    length = len(high)
    high.extend(low[:(5-length)])
    return high
    

def scan_directory_recursive(path, depth, results, state):
    if depth > MAX_DEPTH or state["folders"] >= MAX_FOLDERS:
        return 
    
    try:
        entries = list(os.scandir(path))
    except (PermissionError, FileNotFoundError, OSError):
        return
    
    sampled_file_count = 0
    subfolders = []
    extensions = {}
    mtimes = []
    template_files = []
    
    for entry in entries:
        try:
            if entry.is_file():
                if sampled_file_count < MAX_FILES:
                    name = os.path.splitext(entry.name)[0]
                    ext = os.path.splitext(entry.name)[1].lower()
                    extensions[ext] = extensions.get(ext, 0) + 1
                    st = entry.stat()
                    mtimes.append(st.st_mtime)
                    sampled_file_count += 1
                    state["files"] += 1 #used so that we calculate the 5% of the whole system files count for the decoy allocation 
                    file = {
                        "path": entry.path,
                        "name": name,
                        "ext": ext,
                        "size": st.st_size,
                    }
                    template_files.append(file)
            elif entry.is_dir():
                subfolders.append(entry.path)
        except (PermissionError, FileNotFoundError, OSError) as e:
            continue
    
    if sampled_file_count == 0:
        if subfolders:
            for sub in subfolders: 
                scan_directory_recursive(sub, depth+1, results, state)
        return 
    
    template_files = choose_templates(template_files)

    profile = {
        "path": os.path.normpath(path),
        "sampled_file_count": sampled_file_count,
        "extensions": extensions,
        "mtime": summarize(mtimes),
        "template_files": template_files
    }

    results.append(profile)
    state["folders"] += 1

    for sub in subfolders:
        scan_directory_recursive(sub, depth+1, results, state)

def scan(state):
    roots = get_roots()
    results  = []

    for root in roots:
        scan_directory_recursive(root, 0, results, state)
    
    return results

def compute_recency(mt):
    if mt is None:
        return 0.0
    now = time.time()
    age_in_days = ( now - mt ) / (24*60*60)
    age_in_days = 1 / (1 + age_in_days)
    return age_in_days

def compute_score(profile):
    extensions = profile.get("extensions", {})
    file_count = profile.get("sampled_file_count")
    path = profile.get("path")
    mtime_stats = profile.get("mtime", {})
    mtime_max = mtime_stats.get("max")
    mtime_median = mtime_stats.get("median")

    #-----FILE SCORE-----
    high_count = 0
    low_count = 0
    for ext, count in extensions.items():
        if ext in HIGH_VALUE_EXTS:
            high_count += count
        elif ext in LOW_VALUE_EXTS:
            low_count += count
    
    high_ratio = high_count / (file_count)
    low_ratio = low_count / (file_count)

    # 1.file type score
    e_score = high_ratio * (1 - low_ratio)

    # 2.file confidence boost score
    if high_count > 0:
        f_boost = math.log(high_count + 1) / math.log(MAX_FILES + 1)
    else: 
        f_boost = 0

    file_score = (ALPHA * e_score) + (BETA * f_boost)

    #-----PATH SCORE-----  (based on path preference -> 'Pepper')
    # Path score rationale:
    # - Structural (root OR user): ransomware targets key regions, not cumulative categories
    # - Behavioral (recency + density): prioritizes active and file-dense folders
    # - Final = structural * behavioral: folder must be both reachable and attractive
    
    # 1. root of drive
    if os.path.abspath(path) == os.path.abspath(os.path.splitdrive(path)[0] + "\\"):
        root = 1
    else:
        root = 0

    # 2. main user path
    home = os.path.expanduser("~")
    if os.path.abspath(path).startswith(os.path.abspath(home)):
        user = 1
    else:
        user = 0

    # 3. recent access
    recency = 0.8 * compute_recency(mtime_median) + 0.2 * compute_recency(mtime_max)

    # 4. file density
    density = math.log(file_count + 1) / math.log(MAX_FILES + 1)

    path_score = max(root, user) * ((recency + density)/2)

    """ first try; started without wieghts.
        second try; added wieghts and gave file_score more with 7:3 ratio
        third try; gave path_score mare with 3:7 ratio
        forth try; the best so far, gave path score more weight with 2:8 ratio"""
    final_score = (0.2 * file_score) + (0.8 * path_score)

    return round(final_score, 4)


def allocate_decoys(profiles, total_decoys):
    total_score = 0
    for p in profiles:
        score = compute_score(p)
        total_score += score
        p["score"] = score

    profiles.sort(key=lambda x: x["score"], reverse=True)

    decoys = 0
    for p in profiles:
        if p["score"] > 0 and decoys < total_decoys:
            decoys_in_p = round(p["score"] * (total_decoys / total_score))
            #to not get small folders too many decoys 
            if decoys_in_p > math.floor(p["sampled_file_count"] * 0.1):
                decoys_in_p = max(1, math.floor(p["sampled_file_count"] * 0.1))
            decoys += decoys_in_p
            p["Num_of_decoys"] = decoys_in_p

def decoy_data(profile):
    template_files = profile.get("template_files", [])
    if not template_files :
        return None
    
    #extension
    folder_path = profile["path"]
    template = random.choice(template_files)
    ext = template["ext"]

    #name
    temp_name = template["name"]
    suffixes = ["copy", "backup", "final", "draft", "review"]
    suffix = random.choice(suffixes)
    name = f"{temp_name}_{suffix}"

    #content -> which file to copy from
    content = template["path"]

    return {
        "folder_path": folder_path,
        "name": name,
        "ext": ext,
        "content": content
    }


def create_plan(profiles):
    plan = [] 

    for p in profiles:
        decoys = p.get("Num_of_decoys", 0)
        p["decoy_files"] = []
        if decoys > 0:
            created = 0
            while created < decoys:
                decoy = decoy_data(p)
                if decoy is None:
                    break
                p["decoy_files"].append(decoy)
                plan.append(decoy)
                created += 1
    
    return plan
                
def create_decoys(plan):
    monitorees = []
    for decoy in plan:
        folder_path = decoy["folder_path"]
        source = decoy["content"]
        name = decoy["name"]
        ext = decoy["ext"]
        
        decoy_name = f"{name}{ext}"
        decoy_path = os.path.join(folder_path, decoy_name)
        counter = 1
        while os.path.exists(decoy_path):
            decoy_name = f"{name}({counter}){ext}"
            decoy_path = os.path.join(folder_path, decoy_name)
            counter += 1
        
        try:
            #copy source content and metadata
            shutil.copy2(source, decoy_path)

            #timestamps close to ctime
            now = time.time()
            atime = now
            mtime = now
            os.utime(decoy_path, (atime, mtime))

        except Exception:
            continue           
        
        monitorees.append(decoy_path)

    with open("monitor.json", "w", encoding="utf-8") as f:
        json.dump(monitorees, f, indent=4)


if __name__ == "__main__":
    # Scan user directores
    state = {"folders": 0,
             "files": 0}
    profiles = scan(state)

    #Save JSON manifest
    with open("folder_profiles.json", "w", encoding="utf-8") as f:
        json.dump(profiles, f, indent=4)

    #plan decoys 
    # decoys are only 5% of number of files in the system according to "pepper" 
    total_decoys = round(0.05 * state["files"])
    
    allocate_decoys(profiles, total_decoys)
    plan = create_plan(profiles)
    
    with open("decoy_plan.json", "w", encoding="utf-8") as f:
        json.dump(plan, f, indent=4)

    # create decoys
    create_decoys(plan)



