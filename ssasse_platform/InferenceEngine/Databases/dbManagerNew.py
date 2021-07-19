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
import datetime
import sqlite3
import json
from .. import helper

# DB file
sqlite_path = "ssasse_platform/InferenceEngine/Databases/"
known_columns = ["TARGET_IPADDR", "DEST_IPADDR", "TARGET_MACADDR", "DEST_MACADDR", "SOURCE_PORT", "DEST_PORT", "PROTOCOL", "PROTOCOL_FUNCTION_CODE"]
unique_columns = ["ACTIVE_SCAN_TIME", "PROCESSING"]

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
        #printD("dbManager.__init__()")
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
            #printD("dbManager - creating db file from scratch: {0}".format(sqlite_file))
            f = open("{0}{1}".format(sqlite_path,sqlite_file), "w+")
            f.close()

            conn = sqlite3.connect("{0}{1}".format(sqlite_path,sqlite_file))
            c = conn.cursor()

            # New Evidence Timeline (ONLY new data)
            #printD("dbManager.create() - create table: timeline_new")
            c.execute("""CREATE TABLE IF NOT EXISTS timeline_new (
                ip text,
                value text,
                timestamp text,
                evidence_type text)""")

            # Full Timeline (full entry when new data is seen)
            c.execute("""CREATE TABLE IF NOT EXISTS timeline_full (
                ip text,
                value text,
                timestamp text,
                evidence_type text)""")

            # All Evidence
            #printD("dbManager.create() - create table: all_evidence")
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

    #####
    #
    #####
    def insertVulnerabilityTableEntry(self, sqlite_file, vuln_sqlite_file, identifier, vulnDict):
        self.vulnLock.acquire()
        try:
            allVulnIDs = allIPs(vuln_sqlite_file)
            vulnID = "V_{0}".format(len(allVulnIDs)+1)
            self.insert(vuln_sqlite_file, vulnID, vulnDict, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "New Vulnerability")
            self.insert(sqlite_file, identifier, {"VULNERABILITIES": vulnID}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Vulnerability Pair")
        except Exception as e:
            printD("dbManagerNew.insertVulnerabilityTableEntry() - ERROR: {0}".format(e))
        finally:
            self.vulnLock.release()

    ###############################################################################
    # insert()
    # insert evidence into DB
    ###############################################################################
    def insert(self, sqlite_file, ip, attributeDict, timestamp, evidence_type):
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
            allEvidenceDictBefore = select_all(sqlite_file,ip)
            for column in unique_columns:
                allEvidenceDictBefore.pop(column, None)
            allEvidenceDictAfter = allEvidenceDictBefore

            for key,value in attributeDict.items():
                key = helper.sanitizeKey(key)

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
                        val = helper.sanitizeVal(val)
                        
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
                longestList = 0
                for key,val in attributeDict.items():
                    if type(val) == list:
                        if len(val) > longestList:
                            longestList = len(val)
                    else:
                        if 1 > longestList:
                            longestList = 1
                i = 0
                while i < longestList:
                    attributeDictIndividual = {}
                    for key,val in attributeDict.items():
                        if type(val) == list:
                            if len(val) >= i + 1:
                                attributeDictIndividual[key] = val[i]
                        else:
                            if i == 0:
                                attributeDictIndividual[key] = val
                            
                    newEvidenceStr = json.dumps(attributeDictIndividual)
                    c.execute("""INSERT INTO timeline_full (ip, value, timestamp, evidence_type) VALUES(?, ?, ?, ?)""", (ip, newEvidenceStr, timestamp, evidence_type,))
                    i = i + 1

                # will determine how many individual 'entries' of evidence there are on this timestamp
                longestList = 0
                for key,val in newEvidenceDict.items():
                    if len(val) > longestList:
                        longestList = len(val)

                i = 0
                while i < longestList:
                    newEvidenceDictIndividual = {}
                    for key,val in newEvidenceDict.items():
                        if len(val) >= i + 1:
                            newEvidenceDictIndividual[key] = val[i]
                    newEvidenceStr = json.dumps(newEvidenceDictIndividual)

                    printD("dbManager.insert() - ip: {0}, evidence: {1}".format(ip, newEvidenceDictIndividual))

                    # insert into timeline_new query
                    c.execute("""INSERT INTO timeline_new (ip, value, timestamp, evidence_type) VALUES(?, ?, ?, ?)""", (ip, newEvidenceStr, timestamp, evidence_type,))
                    #printD("dbManager.insert() - after insert into timeline_new")
                    i = i + 1

                allEvidenceStr = json.dumps(allEvidenceDictAfter)
                # update all_evidence query
                c.execute("""INSERT OR REPLACE INTO all_evidence (ip, value) VALUES(?, ?)""", (ip, allEvidenceStr,))
                #printD("dbManager.insert() - after insert into all_evidence")

            conn.commit()
            conn.close()

        except Exception as e:
            printD("dbManager.insert() - ERROR: {0} - ip: {1} - attributeDict: {2}".format(e, ip, attributeDict))
        finally:
            self.lock.release()

        return newEvidenceDict

####################################################################################################
#
#
# select all evidence for a specified IP
####################################################################################################
def select_all(sqlite_file, ip, dictFormat=True):
    #printD("dbManager.select_all() - sqlite_file: {0}, ip: {1}".format(sqlite_file, ip))
    try:
        returnResult = {}

        # check file exists
        f = open("{0}{1}".format(sqlite_path,sqlite_file), "a+")
        f.close()

        conn = sqlite3.connect("{0}{1}".format(sqlite_path,sqlite_file))
        c = conn.cursor()
        c.execute("""SELECT value FROM all_evidence WHERE ip = ?""", (ip,))

        allEvidenceStr = "{}"
        result = c.fetchone()
        if len(result) > 0:
            allEvidenceStr = result[0]

        #printD("dbManager.select_all() - allEvidenceStr: {0}".format(allEvidenceStr))
        returnResult = json.loads(allEvidenceStr)

        # TODO: implement table format
        if not dictFormat:
            pass

        conn.close()

    except Exception as e:
        printD("dbManager.select_all() - ERROR: {0} - ip: {1}".format(e, ip))

    return returnResult

####################################################################################################
#
#
# select chronological timeline of evidence for a specified IP
####################################################################################################
def select_timeline(sqlite_file, ip, newOnly=False, dictFormat=True):
    #printD("dbManager.select_new()")
    try:
        evidenceList = []

        # check file exists
        f = open("{0}{1}".format(sqlite_path,sqlite_file), "a+")
        f.close()

        conn = sqlite3.connect("{0}{1}".format(sqlite_path,sqlite_file))
        c = conn.cursor()

        if newOnly:
            c.execute("""SELECT ip, value, timestamp, evidence_type FROM timeline_new WHERE ip = ? ORDER BY timestamp ASC""", (ip,))
        else:
            c.execute("""SELECT ip, value, timestamp, evidence_type FROM timeline_full WHERE ip = ? ORDER BY timestamp ASC""", (ip,))
        evidenceList = c.fetchall()

        if dictFormat:
            evidenceListDictFormat = []
            for evidence in evidenceList:
                evidenceDict = {}
                evidenceDict["TARGET_IPADDR"] = evidence[0]
                evidenceDict["TIMESTAMP"] = evidence[2]
                evidenceDict["EVIDENCE_TYPE"] = evidence[3]
                value_dict = json.loads(evidence[1])
                for key,val in value_dict.items():
                    evidenceDict[key] = val
                evidenceListDictFormat.append(evidenceDict)
            evidenceList = evidenceListDictFormat

        conn.close()

    except Exception as e:
        printD("dbManager.select_timeline() - ERROR: {0} - ip: {1}".format(e, ip))

    return evidenceList

####################################################################################################
# select a set of colums or all colums from ALL evidence where specified attributes have specified values
# example: select_something_where(DB_FILE, "TARGET_IPADDR,Attribute_01,SCAN_NAME", "Attribute_01=XYZ,Attribute_02=ABC")
# example2: select_something_where(DB_FILE, "*", "Attribute_01=XYZ")
####################################################################################################
def select_something_where(sqlite_file, attributeListStr, whereStatementStr, dictFormat=True):
    try:
        evidenceList = []
        dynamicEvidenceListDict = []

        whereStatementList = whereStatementStr.split(",")
        whereDict = {}
        for item in whereStatementList:
            whereDict[item.split("=")[0]] = item.split("=")[1]

        if attributeListStr == "*":
            attributeList = ["TARGET_IPADDR"]
        else:
            attributeList = attributeListStr.split(",")
            if not dictFormat:
                evidenceList.append(attributeList)

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
                if key == "TARGET_IPADDR" or key == "IP":
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
                if attributeListStr != "*":
                    prepItem = ([],{})[dictFormat]
                    for attribute in attributeList:
                        attributeVal = ""
                        if attribute == "TARGET_IPADDR" or attribute == "ip":
                            attributeVal = ip
                        else:
                            keyName = helper.singleInList(attribute, evidenceDict.keys())
                            if keyName:
                                attributeVal = evidenceDict[keyName]
                        if dictFormat:
                            prepItem[attribute] = attributeVal
                        else:
                            prepItem.append(attributeVal)
                    evidenceList.append(prepItem)
                else:
                    prepItem = evidenceDict
                    prepItem["TARGET_IPADDR"] = ip
                    dynamicEvidenceListDict.append(prepItem)
                    for key in evidenceDict.keys():
                        if key not in attributeList:
                            attributeList.append(key)

        if attributeListStr == "*":
            if not dictFormat:
                evidenceList.append(attributeList)
            for dict in dynamicEvidenceListDict:
                prepItem = ([],{})[dictFormat]
                for attribute in attributeList:
                    if attribute in dict.keys():
                        if dictFormat:
                            prepItem[attribute] = dict[attribute]
                        else:
                            prepItem.append(dict[attribute])
                    else:
                        if dictFormat:
                            #prepItem[attribute] = []
                            pass
                        else:
                            prepItem.append([])
                evidenceList.append(prepItem)

        conn.close()

    except Exception as e:
        printD("dbManager.select_something_where() - ERROR: {0}".format(e))

    return evidenceList

####################################################################################################
# select a set of colums or all colums from TIMELINE evidence where specified attributes have specified values
# example: select_something_where(DB_FILE, "TARGET_IPADDR,SCAN_NAME", "Attribute_01=XYZ,EVIDENCE_TYPE=Passive")
# example2: select_something_where(DB_FILE, "*", "EVIDENCE_TYPE=Passive")
####################################################################################################
def select_something_timeline_where(sqlite_file, attributeListStr, whereStatementStr, newOnly=False, dictFormat=True):
    try:
        evidenceList = []
        dynamicEvidenceListDict = []

        whereStatementList = whereStatementStr.split(",")
        whereDict = {}
        for item in whereStatementList:
            whereDict[item.split("=")[0]] = item.split("=")[1]

        if attributeListStr == "*":
            attributeList = ["TARGET_IPADDR", "TIMESTAMP", "EVIDENCE_TYPE"]
        else:
            attributeList = attributeListStr.split(",")
            if not dictFormat:
                evidenceList.append(attributeList)

        # check file exists
        f = open("{0}{1}".format(sqlite_path,sqlite_file), "a+")
        f.close()

        conn = sqlite3.connect("{0}{1}".format(sqlite_path,sqlite_file))
        c = conn.cursor()

        if newOnly:
            c.execute("""SELECT ip, value, timestamp, evidence_type FROM timeline_new ORDER BY timestamp ASC""")
        else:
            c.execute("""SELECT ip, value, timestamp, evidence_type FROM timeline_full ORDER BY timestamp ASC""")
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
                if attributeListStr != "*":
                    prepItem = ([],{})[dictFormat]
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
                                attributeVal = evidenceDict[keyName]
                        if dictFormat:
                            prepItem[attribute] = attributeVal
                        else:
                            prepItem.append(attributeVal)
                    evidenceList.append(prepItem)
                else:
                    prepItem = evidenceDict
                    prepItem["TARGET_IPADDR"] = ip
                    prepItem["TIMESTAMP"] = timestamp
                    prepItem["EVIDENCE_TYPE"] = evidenceType
                    dynamicEvidenceListDict.append(prepItem)
                    for key in evidenceDict.keys():
                        if key not in attributeList:
                            attributeList.append(key)

        if attributeListStr == "*":
            if not dictFormat:
                evidenceList.append(attributeList)
            for dict in dynamicEvidenceListDict:
                prepItem = ([],{})[dictFormat]
                for attribute in attributeList:
                    if attribute in dict.keys():
                        if dictFormat:
                            prepItem[attribute] = dict[attribute]
                        else:
                            prepItem.append(dict[attribute])
                    else:
                        if dictFormat:
                            #prepItem[attribute] = ""
                            pass
                        else:
                            prepItem.append("")
                evidenceList.append(prepItem)

        conn.close()

    except Exception as e:
        printD("dbManager.select_something_timeline_where() - ERROR: {0}".format(e))

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

###############################################################################
# allAttributes(sqlite_file)
# returns all attribute key names in db
###############################################################################
def allAttributes(sqlite_file, evidenceType = None):
    #printD("dbManager.allAttributes()")
    returnResult = []

    try:
        ips = allIPs(sqlite_file)
        for ip in ips:
            if evidenceType == "Passive":
                evidenceList = select_something_timeline_where(sqlite_file, "*", "EVIDENCE_TYPE=Passive")
                for timelineEvent in evidenceList:
                    for key in timelineEvent.keys():
                        if key not in returnResult:
                            returnResult.append(key)
            elif evidenceType == "Active":
                evidenceList = select_something_timeline_where(sqlite_file, "*", "EVIDENCE_TYPE=Active")
                for timelineEvent in evidenceList:
                    for key in timelineEvent.keys():
                        if key not in returnResult:
                            returnResult.append(key)
            else:
                ipDict = select_all(sqlite_file, ip)
                for key in ipDict.keys():
                    if key not in returnResult:
                        returnResult.append(key)

    except Exception as e:
        printD("dbManager.allAttributes() - ERROR: {0}".format(e))

    return returnResult
