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

NEW_E_DB_FILE = "new_e_db.sqlite" # evidence
DBManagerNew = dbManagerNew.DBManager()

ips = dbManagerNew.allIPs(NEW_E_DB_FILE)

for ip in ips:
    print("printing ALL_EVIDENCE for ip (dict format): {0}".format(ip))
    evidenceDict = dbManagerNew.select_all(NEW_E_DB_FILE, ip)
    for key,values in evidenceDict.items():
        print("{0}: {1}".format(key, values))
    print("")
