import json,os
p=os.path.expanduser("~/Library/Application\ Support/Signal/sql/config.json")
d=json.load(open(p))
arr=d["key"]["data"]
print(bytes(arr).hex())
