import sys
if sys.version_info[0] >= 3:
    unicode = str

import json
from future.utils import viewitems
from io import open
from ssasse_platform.InferenceEngine.Databases import dbManager
import os
import sqlite3

from shutil import copyfile
import re

from ssasse_platform.InferenceEngine import helper

database_path = "ssasse_platform/InferenceEngine/Databases/"

E_DB_FILE = "e_db.sqlite" # evidence
EVENTS_DB_FILE = "events_db.sqlite" # events

E_DB_FILE_CLEAN = "e_db_clean.sqlite" # scrubbed evidence
EVENTS_DB_FILE_CLEAN = "events_db_clean.sqlite" # scrubbed events

copyfile("{0}{1}".format(database_path, E_DB_FILE), "{0}{1}".format(database_path, E_DB_FILE_CLEAN))
copyfile("{0}{1}".format(database_path, EVENTS_DB_FILE), "{0}{1}".format(database_path, EVENTS_DB_FILE_CLEAN))

DBManager = dbManager.DBManager()

# sensitive fields - ip, mac

# E_DB
# identifier
# TARGET_IPADDR
# DEST_IPADDR
# TARGET_MACADDR
# DEST_MACADDR

# EVENTS_DB
# TARGET_IPADDR
# INFO - find and replace

maskedIPs = {}
maskedMACs = {}

ipCounter = 0
macCounter = 0

# find all IPs and map them to masked 
allIPs = dbManager.allIdentifiers(E_DB_FILE)

for deviceIP in allIPs:
    if deviceIP not in maskedIPs.keys():
        maskedIPs[deviceIP] = "IP_{0}".format(ipCounter)
        ipCounter = ipCounter + 1

    evidence = dbManager.select(E_DB_FILE, deviceIP)

    if "TARGET_IPADDR" in evidence.keys():
            for targetIP in evidence["TARGET_IPADDR"]:
                ipKey = helper.singleInList(targetIP, maskedIPs.keys())
                if ipKey == False:
                    maskedIPs[targetIP] = "IP_{0}".format(ipCounter)
                    ipCounter = ipCounter + 1

    if "DEST_IPADDR" in evidence.keys():
            for destIP in evidence["DEST_IPADDR"]:
                ipKey = helper.singleInList(destIP, maskedIPs.keys())
                if ipKey == False:
                    maskedIPs[destIP] = "IP_{0}".format(ipCounter)
                    ipCounter = ipCounter + 1

    if "TARGET_MACADDR" in evidence.keys():
            for targetMAC in evidence["TARGET_MACADDR"]:
                macKey = helper.singleInList(targetMAC, maskedMACs.keys())
                if macKey == False:
                    maskedMACs[targetMAC] = "MAC_{0}".format(macCounter)
                    macCounter = macCounter + 1

    if "DEST_MACADDR" in evidence.keys():
            for destMAC in evidence["DEST_MACADDR"]:
                macKey = helper.singleInList(destMAC, maskedMACs.keys())
                if macKey == False:
                    maskedMACs[destMAC] = "MAC_{0}".format(macCounter)
                    macCounter = macCounter + 1

# find and replace - E_DB_CLEAN
conn = sqlite3.connect("{0}{1}".format(database_path,E_DB_FILE_CLEAN))
c = conn.cursor()

for ip,maskedIP in maskedIPs.items():
    c.execute("""UPDATE identifier SET identifier_value='{0}' WHERE identifier_value = ?""".format(maskedIP), (ip,))
    c.execute("""UPDATE TARGET_IPADDR SET TARGET_IPADDR_value='{0}' WHERE TARGET_IPADDR_value = ?""".format(maskedIP), (ip,))
    c.execute("""UPDATE DEST_IPADDR SET DEST_IPADDR_value='{0}' WHERE DEST_IPADDR_value = ?""".format(maskedIP), (ip,))

for mac,maskedMAC in maskedMACs.items():
    c.execute("""UPDATE TARGET_MACADDR SET TARGET_MACADDR_value='{0}' WHERE TARGET_MACADDR_value = ?""".format(maskedMAC), (mac,))
    c.execute("""UPDATE DEST_MACADDR SET DEST_MACADDR_value='{0}' WHERE DEST_MACADDR_value = ?""".format(maskedMAC), (mac,))

conn.commit()
conn.close()



# find and replace - EVENTS_DB_CLEAN
conn = sqlite3.connect("{0}{1}".format(database_path,EVENTS_DB_FILE_CLEAN))
c = conn.cursor()

for ip,maskedIP in maskedIPs.items():
    c.execute("""UPDATE TARGET_IPADDR SET TARGET_IPADDR_value='{0}' WHERE TARGET_IPADDR_value = ?""".format(maskedIP), (ip,))

for ip,maskedIP in maskedIPs.items():
    c.execute("""UPDATE INFO SET INFO_value = replace(INFO_value, '{0}', '{1}')""".format(ip, maskedIP))

for mac,maskedMAC in maskedMACs.items():
    c.execute("""UPDATE INFO SET INFO_value = replace(INFO_value, '{0}', '{1}')""".format(mac, maskedMAC))

conn.commit()
conn.close()

# make new ssasse.log with obfuscated ips
patIP = re.compile(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
patMAC = re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")
patMAC2 = re.compile(r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})")

fr = open("ssasse.log", "r", encoding="utf-8")
fw = open("ssasse.log.obfuscated", "w+", encoding="utf-8")

for line in fr:
    newLine = line

    # check regex - perform translation on found IPs and MACs

    # IP
    foundIPs = re.findall(patIP, line)
    for ip in foundIPs:
        ipKey = helper.singleInList(ip, maskedIPs.keys())
        if ipKey == False:
            maskedIPs[ip] = "IP_{0}".format(ipCounter)
            ipCounter = ipCounter + 1
            ipKey = ip
        newLine = newLine.replace(ip, maskedIPs[ipKey])

    # MAC
    foundMACs = re.findall(patMAC, line)
    for mac in foundMACs:
        macKey = helper.singleInList(mac, maskedMACs.keys())
        if macKey == False:
            maskedMACs[mac] = "MAC_{0}".format(macCounter)
            macCounter = macCounter + 1
            macKey = mac
        newLine = newLine.replace(mac, maskedMACs[macKey])

    # MAC2 (hyphen)
    foundMACs = re.findall(patMAC2, line)
    for mac in foundMACs:
        macKey = helper.singleInList(mac, maskedMACs.keys())
        if macKey == False:
            maskedMACs[mac] = "MAC_{0}".format(macCounter)
            macCounter = macCounter + 1
            macKey = mac
        newLine = newLine.replace(mac, maskedMACs[macKey])

    # finally write the line
    fw.write(newLine)

fw.close()
fr.close()

print("ips:")
for ipKey,ipVal in maskedIPs.items():
    print("{0}, {1}".format(ipKey, ipVal))

print("macs:")
for macKey,macVal in maskedMACs.items():
    print("{0}, {1}".format(macKey,macVal))
