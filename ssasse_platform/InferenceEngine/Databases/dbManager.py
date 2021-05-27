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

from datetime import time
import sqlite3
import json
from .. import helper

# DB file
sqlite_path = "ssasse_platform/InferenceEngine/Databases/"

import logging
logger = logging.getLogger(__name__)
DEBUG = False
def printD(m):
    if DEBUG:
        logger.debug(m)

import multiprocessing

class DBManager():
    def __init__(self):
        printD("dbManager.__init__()")
        self.lock = multiprocessing.Lock()
        self.vulnLock = multiprocessing.Lock()

    ###############################################################################
    # create(sqlite_file) 
    # Wipe DB and create it from scratch. Will have no records in the tables. 
    ###############################################################################
    def create(self, sqlite_file):
        #printD("dbManager.create()")
        self.lock.acquire()
        try:
            # wipe file
            printD("dbManager - creating db file from scratch: {0}".format(sqlite_file))
            f = open("{0}{1}".format(sqlite_path,sqlite_file), "w+")
            f.close()

            conn = sqlite3.connect("{0}{1}".format(sqlite_path,sqlite_file))
            c = conn.cursor()

            # New Evidence
            printD("dbManager.create() - create table: new_evidence")
            c.execute("""CREATE TABLE IF NOT EXISTS new_evidence (
                id integer PRIMARY KEY,
                ip text,
                value text,
                timestamp text,
                type text)""")

            # All Evidence
            printD("dbManager.create() - create table: all_evidence")
            c.execute("""CREATE TABLE IF NOT EXISTS all_evidence (
                id integer PRIMARY KEY,
                ip text,
                value text)""")

            conn.commit()
            conn.close()

        except Exception as e:
            printD("dbManager.create() - ERROR: {0}".format(e))
        finally:
            self.lock.release()

        return 0

    ###############################################################################
    # insert()
    # insert evidence into DB
    ###############################################################################
    def insert(self, sqlite_file, target_ipaddr, evidence_type, timestamp, attributeDict):
        #printD("dbManager.insert()")
        self.lock.acquire()
        try:
            newEvidenceDict = {}

            # check file exists
            f = open("{0}{1}".format(sqlite_path,sqlite_file), "a+")
            f.close()

            conn = sqlite3.connect("{0}{1}".format(sqlite_path,sqlite_file))
            c = conn.cursor()

            newEvidenceDict = {}
            allEvidenceDictBefore = select_all(sqlite_file,target_ipaddr)
            allEvidenceDictAfter = {}

            for key,values in attributeDict.items():
                key = helper.sanitizeTable(key)

                for value in values:
                    value = helper.sanitizeVal(value)
                    
                    # check if individual evidence piece is in all_evidence
                    newEvidence = False

                    if key not in allEvidenceDictBefore.keys():
                        newEvidence = True
                    elif value not in allEvidenceDictBefore[key]:
                        newEvidence = True

                    if newEvidence:
                        if key not in newEvidenceDict:
                            newEvidenceDict[key] = []
                        if value not in newEvidenceDict[key]:
                            newEvidenceDict[key].append(value)
                    
                        if key not in allEvidenceDictAfter:
                            allEvidenceDictAfter[key] = []
                        if value not in allEvidenceDictAfter[key]:
                            allEvidenceDictAfter[key].append(value)
            
            newEvidenceStr = json.dumps(newEvidenceDict)
            allEvidenceStr = json.dumps(allEvidenceDictAfter)

            # insert into new_evidence query
            c.execute("""INSERT INTO new_evidence (id, ip, value, timestamp, type) VALUES(?)""", (None, target_ipaddr, newEvidenceStr, timestamp, evidence_type,))

            # update all_evidence query
            c.execute("""INSERT OR REPLACE INTO all_evidence (id, ip, value) VALUES((SELECT id FROM all_evidence WHERE ip = ?), ?, ?)""", (target_ipaddr, target_ipaddr, allEvidenceStr,))

            conn.commit()
            conn.close()

        except Exception as e:
            printD("dbManager.insert() - ERROR: {0} - target_ipaddr: {1} - attributeDict: {2}".format(e, target_ipaddr, attributeDict))
        finally:
            self.lock.release()

        return newEvidenceDict

def select_all(sqlite_file, target_ipaddr):
    #printD("dbManager.select_all()")
    try:
        returnResult = {}

        # check file exists
        f = open("{0}{1}".format(sqlite_path,sqlite_file), "a+")
        f.close()

        conn = sqlite3.connect("{0}{1}".format(sqlite_path,sqlite_file))
        c = conn.cursor()

        c.execute("""SELECT value FROM all_evidence WHERE ip = ?""", (target_ipaddr,))
        allEvidenceStr = c.fetchone()[0]
        returnResult = json.loads(allEvidenceStr)

        conn.close()

    except Exception as e:
        printD("dbManager.select_all() - ERROR: {0} - target_ipaddr: {1}".format(e, target_ipaddr))

    return returnResult

def select_new(sqlite_file, target_ipaddr):
    #printD("dbManager.select_new()")
    try:
        newEvidenceList = []

        # check file exists
        f = open("{0}{1}".format(sqlite_path,sqlite_file), "a+")
        f.close()

        conn = sqlite3.connect("{0}{1}".format(sqlite_path,sqlite_file))
        c = conn.cursor()

        c.execute("""SELECT ip, value, timestamp, type FROM new_evidence WHERE ip = ?""", (target_ipaddr,))
        newEvidenceList = c.fetchall()

        conn.close()

    except Exception as e:
        printD("dbManager.select_new() - ERROR: {0} - target_ipaddr: {1}".format(e, target_ipaddr))

    return newEvidenceList