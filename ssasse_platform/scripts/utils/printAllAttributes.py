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

attributes = dbManagerNew.allAttributes(ENEW_DB_FILE)
print("printing ALL_ATTRIBUTES: {0}".format(attributes))

attributes = dbManagerNew.allAttributes(ENEW_DB_FILE, "Passive")
print("printing ALL_ATTRIBUTES (Passive): {0}".format(attributes))

attributes = dbManagerNew.allAttributes(ENEW_DB_FILE, "Active")
print("printing ALL_ATTRIBUTES (Active): {0}".format(attributes))
