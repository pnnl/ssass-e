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
DEBUG = True
def printD(m):
    if DEBUG:
        logger.debug(m)
        print(m)

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
        printD("dbManager.create()")
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
                ip text,
                value text,
                timestamp text,
                type text)""")

            # All Evidence
            printD("dbManager.create() - create table: all_evidence")
            c.execute("""CREATE TABLE IF NOT EXISTS all_evidence (
                ip text UNIQUE,
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
    def insert(self, sqlite_file, target_ipaddr, attributeDict, timestamp, evidence_type):
        printD("dbManager.insert()")
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
            allEvidenceDictAfter = allEvidenceDictBefore

            for key,value in attributeDict.items():
                key = helper.sanitizeTable(key)

                if type(value) == str:
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

                elif type(value) == list:
                    for val in value:
                        val = helper.sanitizeVal(value)
                        
                        # check if individual evidence piece is in all_evidence
                        newEvidence = False

                        if key not in allEvidenceDictBefore.keys():
                            newEvidence = True
                        elif val not in allEvidenceDictBefore[key]:
                            newEvidence = True

                        if newEvidence:
                            if key not in newEvidenceDict:
                                newEvidenceDict[key] = []
                            if val not in newEvidenceDict[key]:
                                newEvidenceDict[key].append(val)
                        
                            if key not in allEvidenceDictAfter:
                                allEvidenceDictAfter[key] = []
                            if val not in allEvidenceDictAfter[key]:
                                allEvidenceDictAfter[key].append(val)
            
            if newEvidenceDict != {}:
                newEvidenceStr = json.dumps(newEvidenceDict)
                allEvidenceStr = json.dumps(allEvidenceDictAfter)

                printD("dbManager.insert() - ip: {0}, evidence: {1}".format(target_ipaddr, newEvidenceDict))

                # insert into new_evidence query
                c.execute("""INSERT INTO new_evidence (ip, value, timestamp, type) VALUES(?, ?, ?, ?)""", (target_ipaddr, newEvidenceStr, timestamp, evidence_type,))
                printD("dbManager.insert() - after insert into new_evidence")

                # update all_evidence query
                c.execute("""INSERT OR REPLACE INTO all_evidence (ip, value) VALUES(?, ?)""", (target_ipaddr, allEvidenceStr,))
                printD("dbManager.insert() - after insert into all_evidence")

            conn.commit()
            conn.close()

        except Exception as e:
            printD("dbManager.insert() - ERROR: {0} - target_ipaddr: {1} - attributeDict: {2}".format(e, target_ipaddr, attributeDict))
        finally:
            self.lock.release()

        return newEvidenceDict

####################################################################################################
#
#
#
####################################################################################################
def select_all(sqlite_file, target_ipaddr):
    printD("dbManager.select_all() - sqlite_file: {0}, target_ipaddr: {1}".format(sqlite_file, target_ipaddr))
    try:
        returnResult = {}

        # check file exists
        f = open("{0}{1}".format(sqlite_path,sqlite_file), "a+")
        f.close()

        conn = sqlite3.connect("{0}{1}".format(sqlite_path,sqlite_file))
        c = conn.cursor()
        c.execute("""SELECT value FROM all_evidence WHERE ip = ?""", (target_ipaddr,))

        allEvidenceStr = "{}"
        result = c.fetchone()
        if len(result) > 0:
            allEvidenceStr = result[0]

        printD("dbManager.select_all() - allEvidenceStr: {0}".format(allEvidenceStr))
        returnResult = json.loads(allEvidenceStr)

        conn.close()

    except Exception as e:
        printD("dbManager.select_all() - ERROR: {0} - target_ipaddr: {1}".format(e, target_ipaddr))

    return returnResult

####################################################################################################
#
#
#
####################################################################################################
def select_timeline(sqlite_file, target_ipaddr):
    #printD("dbManager.select_new()")
    try:
        evidenceList = []

        # check file exists
        f = open("{0}{1}".format(sqlite_path,sqlite_file), "a+")
        f.close()

        conn = sqlite3.connect("{0}{1}".format(sqlite_path,sqlite_file))
        c = conn.cursor()

        c.execute("""SELECT ip, value, timestamp, type FROM new_evidence WHERE ip = ? ORDER BY timestamp ASC""", (target_ipaddr,))
        evidenceList = c.fetchall()

        conn.close()

    except Exception as e:
        printD("dbManager.select_timeline() - ERROR: {0} - target_ipaddr: {1}".format(e, target_ipaddr))

    return evidenceList

####################################################################################################
#
#
#
####################################################################################################
def select_something_where(sqlite_file, attributeList, whereDict):
    try:
        evidenceList = []

        # check file exists
        f = open("{0}{1}".format(sqlite_path,sqlite_file), "a+")
        f.close()

        conn = sqlite3.connect("{0}{1}".format(sqlite_path,sqlite_file))
        c = conn.cursor()

        c.execute("""SELECT ip, value FROM all_evidence""")
        rawList = c.fetchall()

        for item in rawList:
            ip = item[0]
            evidenceDict = json.loads(item[1])

            matchFound = True

            for key,val in whereDict.items():
                if key == "TARGET_IPADDR":
                    if ip != val:
                        matchFound = False
                        break
                else:
                    if key in evidenceDict.keys():
                        if not helper.singleInList(val, evidenceDict[key]):
                            matchFound = False
                            break
                    else:
                        matchFound = False
                        break
            
            if matchFound:
                prepItem = []
                for attribute in attributeList:
                    attributeVal = ""
                    if attribute == "TARGET_IPADDR":
                        attributeVal = ip
                    else:
                        keyName = helper.singleInList(attribute, evidenceDict.keys())
                        if keyName:
                            attributeVal = evidenceDict[keyName]
                    prepItem.append(attributeVal)
                evidenceList.append(prepItem)

        conn.close()

    except Exception as e:
        printD("dbManager.select_something_where() - ERROR: {0}".format(e))

    return evidenceList

####################################################################################################
#
#
#
####################################################################################################
def select_something_timeline_where(sqlite_file, attributeList, whereDict):
    try:
        evidenceList = []

        # check file exists
        f = open("{0}{1}".format(sqlite_path,sqlite_file), "a+")
        f.close()

        conn = sqlite3.connect("{0}{1}".format(sqlite_path,sqlite_file))
        c = conn.cursor()

        c.execute("""SELECT ip, value, timestamp, type FROM new_evidence ORDER BY timestamp ASC""")
        rawList = c.fetchall()

        for item in rawList:
            ip = item[0]
            evidenceDict = json.loads(item[1])
            timestamp = item[2]
            evidenceType = item[3]

            matchFound = True

            for key,val in whereDict.items():
                if key == "TARGET_IPADDR":
                    if ip != val:
                        matchFound = False
                        break
                elif key == "TIMESTAMP": 
                    if timestamp != val:
                        matchFound = False
                        break
                elif key == "EVIDENCE_TYPE": 
                    if evidenceType != val:
                        matchFound = False
                        break
                else:
                    if key in evidenceDict.keys():
                        if not helper.singleInList(val, evidenceDict[key]):
                            matchFound = False
                            break
                    else:
                        matchFound = False
                        break
            
            if matchFound:
                prepItem = []
                for attribute in attributeList:
                    attributeVal = ""
                    if attribute == "TARGET_IPADDR":
                        attributeVal = ip
                    elif attribute == "TIMESTAMP":
                        attributeVal = timestamp
                    elif attribute == "EVIDENCE_TYPE":
                        attributeVal = evidenceType
                    else:
                        keyName = helper.singleInList(attribute, evidenceDict.keys())
                        if keyName:
                            attributeVal = evidenceDict[key]
                    prepItem.append(attributeVal)
                evidenceList.append(prepItem)

        conn.close()

    except Exception as e:
        printD("dbManager.select_something_where() - ERROR: {0}".format(e))

    return evidenceList

###############################################################################
# allIPs(sqlite_file)
# returns all ips in db
###############################################################################
def allIPs(sqlite_file):
    #printD("dbManager.allIPs()")
    returnResult = []

    try:

        # check file exists
        f = open("{0}{1}".format(sqlite_path,sqlite_file), "a+")
        f.close()

        conn = sqlite3.connect("{0}{1}".format(sqlite_path,sqlite_file))
        c = conn.cursor()

        # check if table exists for identifier
        c.execute("""SELECT EXISTS(SELECT name FROM sqlite_master WHERE type='table' AND name = ?)""", ("all_evidence",))
        result = c.fetchone()[0]

        if result != 0:
            # get all identifier values
            c.execute("""SELECT ip FROM all_evidence""")
            result = c.fetchall()
            for item in result:
                returnResult.append(item[0])

        conn.close()

    except Exception as e:
        printD("dbManager.allIPs() - ERROR: {0}".format(e))

    return returnResult