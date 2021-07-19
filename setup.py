# -*- coding: utf-8 -*- {{{
# vim: set fenc=utf-8 ft=python sw=4 ts=4 sts=4 et:
#
#       Copyright (2021) Battelle Memorial Institute
#                      All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# }}}

import sys
if sys.version_info[0] >= 3:
    unicode = str

import json
from io import open
from ssasse_platform.InferenceEngine.Databases import dbManager
from ssasse_platform.InferenceEngine.Databases import dbManagerNew
import os
import subprocess

import multiprocessing

from ssasse_platform.InferenceEngine import helper

database_path = "ssasse_platform/InferenceEngine/Databases/"
profiles_path = "ssasse_platform/InferenceEngine/Profiles/"

# Create fresh databases
NEW_E_DB_FILE = "new_e_db.sqlite" # new evidence
NEW_EVENTS_DB_FILE = "new_events_db.sqlite" # new events
NEW_D_DB_FILE = "new_d_db.sqlite" # new devices
NEW_V_DB_FILE = "new_v_db.sqlite" # new vendors
NEW_VULN_DB_FILE = "new_vuln_db.sqlite" # new vulns
NEW_R_DB_FILE = "new_r_db.sqlite" # new requests/notifs

D_DB_FILE = "d_db.sqlite" # devices
V_DB_FILE = "v_db.sqlite" # vendors
VULN_DB_FILE = "vuln_db.sqlite" # vulnerabilities
S_DB_FILE = "s_db.sqlite" # status
R_DB_FILE = "r_db.sqlite" # requests/notifications

DBManager = dbManager.DBManager()
DBManagerNew = dbManagerNew.DBManager()

DBManagerNew.create(NEW_E_DB_FILE)
DBManagerNew.create(NEW_EVENTS_DB_FILE)
DBManagerNew.create(NEW_D_DB_FILE)
DBManagerNew.create(NEW_V_DB_FILE)
DBManagerNew.create(NEW_VULN_DB_FILE)
DBManagerNew.create(NEW_R_DB_FILE)

DBManager.create(D_DB_FILE)
DBManager.create(V_DB_FILE)
DBManager.create(VULN_DB_FILE)
DBManager.create(S_DB_FILE)
DBManager.create(R_DB_FILE)

# Load vendor profiles from .json file, insert into V_DB
for file in os.listdir(profiles_path+"Vendors/"):
    if file.endswith(".json"):
        name = file.split(".json")[0]
        fr = open("{0}{1}".format(profiles_path+"Vendors/", file), "r", encoding="utf-8")
        try:
            profile = json.loads(fr.read())
        except:
            profile = "NA"
        fr.close()
        if profile != "NA":
            newProfile = helper.breakDownDict(profile)
            print("Inserting vendor profile {0}".format(name))
            DBManager.insert(V_DB_FILE, name, newProfile)


# Load vendor profiles from .json file, insert into NEW_V_DB
for file in os.listdir(profiles_path+"Vendors/"):
    if file.endswith(".json"):
        name = file.split(".json")[0]
        fr = open("{0}{1}".format(profiles_path+"Vendors/", file), "r", encoding="utf-8")
        try:
            profile = json.loads(fr.read())
        except:
            profile = "NA"
        fr.close()
        if profile != "NA":
            newProfile = helper.breakDownDict(profile)
            print("Inserting vendor profile {0}".format(name))
            DBManagerNew.insert(NEW_V_DB_FILE, name, newProfile)


# Devices
for file in os.listdir(profiles_path+"Devices/"):
    if file.endswith(".json"):
        name = file.split(".json")[0]
        fr = open("{0}{1}".format(profiles_path+"Devices/", file), "r", encoding="utf-8")
        try:
            profile = json.loads(fr.read())
        except:
            profile = "NA"
        fr.close()
        if profile != "NA":
            newProfile = helper.breakDownDict(profile, "", {})
            print("Inserting device profile {0}".format(name))
            DBManager.insert(D_DB_FILE, name, newProfile, "", "CREATION")


# Devices
for file in os.listdir(profiles_path+"Devices/"):
    if file.endswith(".json"):
        name = file.split(".json")[0]
        fr = open("{0}{1}".format(profiles_path+"Devices/", file), "r", encoding="utf-8")
        try:
            profile = json.loads(fr.read())
        except:
            profile = "NA"
        fr.close()
        if profile != "NA":
            newProfile = helper.breakDownDict(profile, "", {})
            print("Inserting device profile {0}".format(name))
            DBManagerNew.insert(NEW_D_DB_FILE, name, newProfile, "", "CREATION")


# Status
DBManager.insert(S_DB_FILE, "ID_QUEUE", {"IP": []})
DBManager.insert(S_DB_FILE, "VULN_QUEUE", {"IP": []})
DBManager.insert(S_DB_FILE, "IDENTIFIED", {"IP": []})
DBManager.insert(S_DB_FILE, "COMPLETED", {"IP": []})
DBManager.insert(S_DB_FILE, "DECK", {"IP": []})

# Requests

# Known CVEs
fr = open("ssasse_platform/InferenceEngine/Databases/known_cves.json", "r", encoding="utf-8")
knownDict = json.loads(fr.read())
fr.close()

devices = dbManager.allIdentifiers(D_DB_FILE)
for device in devices:
    if device in knownDict.keys():
        for cveDict in knownDict[device]:
            #print("Inserting vuln {0} into {1}".format(cveDict,device))
            DBManager.insertVulnerabilityTableEntry(D_DB_FILE, VULN_DB_FILE, device, cveDict)

print("inference prep done")
