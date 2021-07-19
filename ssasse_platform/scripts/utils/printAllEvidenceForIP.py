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

print("printing ALL_EVIDENCE for ip (dict format): {0}".format(ip))
evidenceDict = dbManagerNew.select_all(ENEW_DB_FILE, ip, True)
for key,values in evidenceDict.items():
    print("{0}: {1}".format(key, values))
