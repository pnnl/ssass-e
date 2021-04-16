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
from future.utils import viewitems
from io import open
from ssasse_platform.InferenceEngine.Databases import dbManager
import os
import subprocess

import multiprocessing

from ssasse_platform.InferenceEngine import helper

database_path = "/"
profiles_path = "../Profiles/"

E_DB_FILE = "e_db.sqlite" # evidence
D_DB_FILE = "d_db.sqlite" # devices
V_DB_FILE = "v_db.sqlite" # vendors
VULN_DB_FILE = "vuln_db.sqlite" # vulnerabilities
EVENTS_DB_FILE = "events_db.sqlite" # events
S_DB_FILE = "s_db.sqlite"

DBManager = dbManager.DBManager()

fr = open("known_cves.json", "r", encoding="utf-8")
knownDict = json.loads(fr.read())
fr.close()

IPs = dbManager.allIdentifiers(E_DB_FILE)
for ip in IPs:
    models = dbManager.select(E_DB_FILE, ip).get("MODEL", [])
    for model in knownDict.keys():
        if model in models:
            for cveDict in knownDict[model]:
                #print("Inserting vuln {0} into {1}".format(cveDict,ip))
                DBManager.insertVulnerabilityTableEntry(E_DB_FILE, VULN_DB_FILE, ip, cveDict)
            break
