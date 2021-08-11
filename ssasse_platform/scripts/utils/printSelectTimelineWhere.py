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

print("argv: {0}".format(sys.argv))

attributeListStr = sys.argv[1]
whereStatementStr = sys.argv[2]

print("attr: {0}, where: {1}".format(attributeListStr, whereStatementStr))
evidenceList = dbManagerNew.select_something_timeline_where(ENEW_DB_FILE, attributeListStr, whereStatementStr, True, True)
print("printing NEW evidence list after select something where (dict format)")
for item in evidenceList:
    print("{0}".format(item))

print("")
print("")
print("")

evidenceList = dbManagerNew.select_something_timeline_where(ENEW_DB_FILE, attributeListStr, whereStatementStr, True, False)
print("printing NEW evidence list after select something where (table format)")
for item in evidenceList:
    print("{0}".format(item))

print("")
print("")
print("")

evidenceList = dbManagerNew.select_something_timeline_where(ENEW_DB_FILE, attributeListStr, whereStatementStr, False, True)
print("printing FULL evidence list after select something where (dict format)")
for item in evidenceList:
    print("{0}".format(item))

print("")
print("")
print("")

evidenceList = dbManagerNew.select_something_timeline_where(ENEW_DB_FILE, attributeListStr, whereStatementStr, False, False)
print("printing FULL evidence list after select something where (table format)")
for item in evidenceList:
    print("{0}".format(item))
