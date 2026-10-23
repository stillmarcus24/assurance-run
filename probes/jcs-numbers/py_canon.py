import json, sys
# json.loads preserves float-ness; 1.0 stays a float, not an int.
for line in sys.stdin:
    line = line.strip()
    if line:
        print(json.dumps(json.loads(line)))
