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
DBManagerNew.create(ENEW_DB_FILE)

DBManagerNew.insert(ENEW_DB_FILE, "192.168.0.1", {"TARGET_IPADDR": "192.168.0.1", "PROTOCOL": "DNP3", "PORT": "21"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Passive")
time.sleep(0.2)

DBManagerNew.insert(ENEW_DB_FILE, "192.168.0.1", {"TARGET_IPADDR": "192.168.0.1", "PROTOCOL": "DNP3", "PORT": "22"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Passive")
time.sleep(0.2)

DBManagerNew.insert(ENEW_DB_FILE, "192.168.0.1", {"TARGET_IPADDR": "192.168.0.1", "PROTOCOL": "MODBUS", "PORT": "23"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Passive")
time.sleep(0.2)

DBManagerNew.insert(ENEW_DB_FILE, "192.168.0.1", {"TARGET_IPADDR": "192.168.0.1", "Attribute_01": "Value_01", "Attribute_02": "Value_02"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Passive")
time.sleep(0.2)

DBManagerNew.insert(ENEW_DB_FILE, "192.168.0.1", {"TARGET_IPADDR": "192.168.0.1", "Attribute_01": "Value_02", "Attribute_02": "Value_02"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Passive")
time.sleep(0.2)

DBManagerNew.insert(ENEW_DB_FILE, "192.168.0.1", {"TARGET_IPADDR": "192.168.0.1", "Attribute_01": "Value_03", "Attribute_02": "Value_02"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Passive")
time.sleep(0.2)



time.sleep(1)



DBManagerNew.insert(ENEW_DB_FILE, "192.168.0.1", {"TARGET_IPADDR": "192.168.0.1", "SCAN_NAME": "Scan_01", "Results_01": "Value_03"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Active")
time.sleep(0.2)

DBManagerNew.insert(ENEW_DB_FILE, "192.168.0.1", {"TARGET_IPADDR": "192.168.0.1", "SCAN_NAME": "Scan_01", "Results_01": "Value_04"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Active")
time.sleep(0.2)

DBManagerNew.insert(ENEW_DB_FILE, "192.168.0.1", {"TARGET_IPADDR": "192.168.0.1", "SCAN_NAME": "Scan_01", "Results_02": "Value_03"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Active")
time.sleep(0.2)

DBManagerNew.insert(ENEW_DB_FILE, "192.168.0.1", {"TARGET_IPADDR": "192.168.0.1", "SCAN_NAME": "Scan_01", "Results_02": "Value_04"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Active")
time.sleep(0.2)

DBManagerNew.insert(ENEW_DB_FILE, "192.168.0.1", {"TARGET_IPADDR": "192.168.0.1", "SCAN_NAME": "Scan_01", "Results_02": "Value_04"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Active")
time.sleep(0.2)



time.sleep(1)



DBManagerNew.insert(ENEW_DB_FILE, "192.168.0.2", {"TARGET_IPADDR": "192.168.0.2", "PROTOCOL": "DNP3", "PORT": "34"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Passive")
time.sleep(0.2)

DBManagerNew.insert(ENEW_DB_FILE, "192.168.0.2", {"TARGET_IPADDR": "192.168.0.2", "PROTOCOL": "DNP3", "PORT": "35"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Passive")
time.sleep(0.2)

DBManagerNew.insert(ENEW_DB_FILE, "192.168.0.2", {"TARGET_IPADDR": "192.168.0.2", "PROTOCOL": "MODBUS", "PORT": "36"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Passive")
time.sleep(0.2)

DBManagerNew.insert(ENEW_DB_FILE, "192.168.0.2", {"TARGET_IPADDR": "192.168.0.2", "Attribute_01": "Value_01", "Attribute_02": "Value_02"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Passive")
time.sleep(0.2)

DBManagerNew.insert(ENEW_DB_FILE, "192.168.0.2", {"TARGET_IPADDR": "192.168.0.2", "Attribute_01": "Value_02", "Attribute_02": "Value_02"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Passive")
time.sleep(0.2)

DBManagerNew.insert(ENEW_DB_FILE, "192.168.0.2", {"TARGET_IPADDR": "192.168.0.2", "Attribute_01": "Value_03", "Attribute_02": "Value_02"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Passive")
time.sleep(0.2)



time.sleep(1)



DBManagerNew.insert(ENEW_DB_FILE, "192.168.0.2", {"TARGET_IPADDR": "192.168.0.2", "SCAN_NAME": "Scan_01", "Results_01": "Value_03"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Active")
time.sleep(0.2)

DBManagerNew.insert(ENEW_DB_FILE, "192.168.0.2", {"TARGET_IPADDR": "192.168.0.2", "SCAN_NAME": "Scan_01", "Results_01": "Value_04"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Active")
time.sleep(0.2)

DBManagerNew.insert(ENEW_DB_FILE, "192.168.0.2", {"TARGET_IPADDR": "192.168.0.2", "SCAN_NAME": "Scan_01", "Results_02": "Value_03"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Active")
time.sleep(0.2)

DBManagerNew.insert(ENEW_DB_FILE, "192.168.0.2", {"TARGET_IPADDR": "192.168.0.2", "SCAN_NAME": "Scan_01", "Results_02": "Value_04"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Active")
time.sleep(0.2)

DBManagerNew.insert(ENEW_DB_FILE, "192.168.0.2", {"TARGET_IPADDR": "192.168.0.2", "SCAN_NAME": "Scan_01", "Results_02": "Value_04"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Active")
time.sleep(0.2)