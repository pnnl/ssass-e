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

print("printing NEW evidence TIMELINE for ip (dict format): {0}".format(ip))
evidenceTimeline = dbManagerNew.select_timeline(ENEW_DB_FILE, ip, True, True)
for item in evidenceTimeline:
    print("{0}".format(item))

print("")
print("")
print("")

print("printing NEW evidence TIMELINE for ip (table format): {0}".format(ip))
evidenceTimeline = dbManagerNew.select_timeline(ENEW_DB_FILE, ip, True, False)
for item in evidenceTimeline:
    print("{0}".format(item))

print("")
print("")
print("")

print("printing FULL evidence TIMELINE for ip (dict format): {0}".format(ip))
evidenceTimeline = dbManagerNew.select_timeline(ENEW_DB_FILE, ip, False, True)
for item in evidenceTimeline:
    print("{0}".format(item))

print("")
print("")
print("")

print("printing FULL evidence TIMELINE for ip (table format): {0}".format(ip))
evidenceTimeline = dbManagerNew.select_timeline(ENEW_DB_FILE, ip, False, False)
for item in evidenceTimeline:
    print("{0}".format(item))
