import sys
if sys.version_info[0] >= 3:
    unicode = str

import json
from ssasse_platform.InferenceEngine.Databases import dbManagerNew
from ssasse_platform.InferenceEngine import helper
import datetime
import time

database_path = "ssasse_platform/InferenceEngine/Databases/"
profiles_path = "ssasse_platform/InferenceEngine/Profiles/"

ENEW_DB_FILE = "enew_db.sqlite" # evidence
DBManagerNew = dbManagerNew.DBManager()

ip = sys.argv[1]

print("printing ALL_EVIDENCE for ip: {0}".format(ip))
evidenceDict = dbManagerNew.select_all(ENEW_DB_FILE, ip)
for key,values in evidenceDict.items():
    print("{0}: {1}".format(key, values))

print("")
print("")
print("")

print("printing evidence TIMELINE for ip: {0}".format(ip))
evidenceTimeline = dbManagerNew.select_timeline(ENEW_DB_FILE, ip)
for item in evidenceTimeline:
    print("{0}".format(item))

print("")
print("")
print("")

attributeListStr = sys.argv[2]
attributeList = attributeListStr.split(",")

whereStatementStr = sys.argv[3]
whereStatementList = whereStatementStr.split(",")
whereDict = {}
for item in whereStatementList:
    whereDict[item.split("=")[0]] = item.split("=")[1]

evidenceList = dbManagerNew.select_something_where(ENEW_DB_FILE, attributeList, whereDict)
print("printing evidence list after select something where")
for item in evidenceList:
    print("{0}".format(item))