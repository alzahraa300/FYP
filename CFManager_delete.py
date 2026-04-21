import os, json

with open("monitor.json", "r", encoding="utf-8") as f:
    paths = json.load(f)

for p in paths:
    p = os.path.normpath(p)
    if os.path.isfile(p):
        try:
            os.remove(p)
            print("Deleted:", p)
        except Exception as e:
            print("Failed :", p, "->", e)
    else:
        print("Missing:", p)