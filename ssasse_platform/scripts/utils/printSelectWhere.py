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

attributeListStr = sys.argv[1]
whereStatementStr = sys.argv[2]

evidenceList = dbManagerNew.select_something_where(ENEW_DB_FILE, attributeListStr, whereStatementStr, True)
print("printing evidence list after select something where (dict format)")
for item in evidenceList:
    print("{0}".format(item))

print("")
print("")
print("")

evidenceList = dbManagerNew.select_something_where(ENEW_DB_FILE, attributeListStr, whereStatementStr, False)
print("printing evidence list after select something where (table format)")
for item in evidenceList:
    print("{0}".format(item))