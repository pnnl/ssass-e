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

import logging
from setup import DBManagerNew
logger = logging.getLogger(__name__)
DEBUG = True
def printD(m):
    if DEBUG:
        logger.debug(m)

import sys
if sys.version_info[0] >= 3:
    unicode = str

import os
import json
from os import listdir
from os.path import isfile, join
from math import *
from io import open
import gevent
from gevent.subprocess import Popen, PIPE
from gevent import socket as gsock
from time import sleep
import time
import datetime
import subprocess
import multiprocessing
from ..common.rmq_connection import RabbitMqConnection
from ..common.actor import Actor

import sqlite3
import json
from .Databases import dbManager
from .Databases import dbManagerNew

#from . import decision_tree_design
from . import decisionSimple
from . import helper

from ipaddress import ip_address, ip_network
from cryptography.fernet import Fernet

# Database files
NEW_E_DB_FILE = "new_e_db.sqlite" # new evidence
NEW_EVENTS_DB_FILE = "new_events_db.sqlite" # new events

E_DB_FILE = "e_db.sqlite" # evidence
D_DB_FILE = "d_db.sqlite" # devices
V_DB_FILE = "v_db.sqlite" # vendors
VULN_DB_FILE = "vuln_db.sqlite" # vulnerabilities
EVENTS_DB_FILE = "events_db.sqlite" # events

MANUF_FILE = "manuf.txt"

# Scan files

# Paths
database_path = "ssasse_platform/InferenceEngine/Databases/"
scans_path = "ssasse_platform/InferenceEngine/Scans/"
results_path = "ssasse_platform/InferenceEngine/Results/"
profiles_path = "ssasse_platform/InerenceEngine/Profiles/"

class BaseMysteryEvidenceProcessor(object):
    def __init__(self, config, DBManager, DBManagerNew, rmq_connection):
        printD("BaseMysteryEvidenceProcessor.__init__()")
#        super(BaseMysteryEvidenceProcessor, self).__init__(config, rmq_connection)

        self.DBManager = DBManager
        self.DBManagerNew = DBManagerNew
        self.publishLock = multiprocessing.Lock()
        self.identified = "n"
        self.resultsDict = {}
        self.resultsDict["internal"] = []
        self.resultsDict["external"] = []
    ##########################################################
    # OUILookUp
    ##########################################################
    def OUILookUp(self, mac):
        #printD("IpProcessor.OUILookUp()")
        mac = mac[0:8].upper()
        fr = open("{0}{1}".format(database_path,MANUF_FILE), "r+", encoding="utf-8")
        manuf = fr.readlines()
        fr.close()

        vendor = "NA"
        for line in manuf:
            line = line.upper()
            if mac in line:
                line = line.split('\t')
                vendor = line[1]
                break

        printD("baseProcessEvidence.OUILookUp() - MAC OUI LOOKUP VENDOR - {0} for {1}".format(vendor,mac))
        return vendor.upper()

    ##########################################################
    # infer()
    ##########################################################
    def infer(self, mysteryDevice, port=''):
        printD("BaseMysteryEvidenceProcessor.infer()")
        scan = "NA"
        kwargs = dict()
        kwargs['port'] = port
        mysteryEvidence = dbManagerNew.select_all(NEW_E_DB_FILE, mysteryDevice)
        allEvents = dbManagerNew.select_all(NEW_EVENTS_DB_FILE, mysteryDevice)

#        def set_connection_ready():
#           printD("ready")
#        rmq_connection = RabbitMqConnection('inference', '5671')
#        rmq_connection.connect(connection_callback=set_connection_ready)

#        time.sleep(3)

        #while not self.connection_ready:
        #    gevent.sleep()

        # no scan outbound
        if ("ACTIVE_SCAN_TIME" not in allEvents.keys()) or ("ACTIVE_SCAN_TIME" in allEvents.keys() and "0" in allEvents["ACTIVE_SCAN_TIME"]):
            printD("ACTIVE_SCAN_TIME")
            scan = self.determineScan(mysteryDevice, **kwargs)
            timeElapsed = 0

        # scan outbound, check timeout
        else:
            activeScanTime = 0
            if "ACTIVE_SCAN_TIME" in allEvents.keys():
                activeScanTime = float(allEvents["ACTIVE_SCAN_TIME"][0])
            timeElapsed = time.time() - activeScanTime

            if timeElapsed > 600:
                #self.DBManager.removeKey(E_DB_FILE, mysteryDevice, "ACTIVE_SCAN_TIME")
                #self.DBManager.insert(E_DB_FILE, mysteryDevice, {"ACTIVE_SCAN_TIME": ["0"]})
                self.DBManagerNew.insert(NEW_EVENTS_DB_FILE, mysteryDevice, {"ACTIVE_SCAN_TIME": ["0"]}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Tracking - Active Scan Time")
                scan = self.determineScan(mysteryDevice, **kwargs)
                printD("baseProcessEvidence.infer() - Not skipping scan {0} for {1}, time elapsed {2}s".format(scan, mysteryDevice, timeElapsed))
            else:
                printD("baseProcessEvidence.infer() - Skipping scan {0} for {1}, time elapsed only {2}s".format(scan, mysteryDevice, timeElapsed))

        # scan going outbound
        if scan != "NA":
            printD("baseProcessEvidence.infer() - ip: {0}, chosenScan: {1}, timeElapsed: {2}".format(mysteryDevice, scan, timeElapsed))
            #self.DBManager.removeKey(E_DB_FILE, mysteryDevice, "ACTIVE_SCAN_TIME")
            #self.DBManager.insert(E_DB_FILE, mysteryDevice, {"ACTIVE_SCAN_TIME": [time.time()]})
            self.DBManagerNew.insert(NEW_EVENTS_DB_FILE, mysteryDevice, {"ACTIVE_SCAN_TIME": [str(time.time())]}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Tracking - Active Scan Time")

        # Determine who to send it to
        siteName = self.getSiteName(mysteryDevice)
        printD("SN: infer() method, scan before requestScan: {}, site: {}".format(scan, siteName))

        # Send active scan
        if scan!= "NA" and siteName != "NA":
            self.requestScan(mysteryDevice, scan, siteName)
           # rmq_connection.send_message("active.requests.{0}".format(siteName), scan["PARAMS"])
           # time.sleep(1)
        #rmq_connection.close_connection()

    #####
    #
    #####
    def getSiteName(self, mysteryDevice):
        fr = open("{0}zonemap.json".format(scans_path), "r", encoding="utf-8")
        zonemap = json.loads(fr.read())
        fr.close()
        siteName = "NA"

        for key,val in zonemap.items():
            # Exact IP match
            if mysteryDevice in val:
                return key

        for key,val in zonemap.items():
            # Check if IP in range
            for ip in val:
                try:
                    ipObj = ip_address(mysteryDevice)
                    netObj = ip_network(ip)
                    if ipObj in netObj:
                        return key
                except Exception as e:
                    printD("checking zonemap for ip warning: {0}".format(e))
        return "NA"


    ##########################################################
    # checkPolicy()
    # Check policy if scan is allowed
    ##########################################################
    def checkPolicy(self, mysteryDevice, scanOrCategoryName):
        #printD("BaseMysteryEvidenceProcessor.checkPolicy()")
        fr = open("{0}policy.json".format(scans_path), "r", encoding="utf-8")
        policy = json.loads(fr.read())
        fr.close()

        fr = open("{0}scans.json".format(scans_path), "r", encoding="utf-8")
        scans = json.loads(fr.read())
        fr.close()

        allowed = False
        keyList = []

        # find exact IP match
        for key in policy.keys():
            if key == mysteryDevice:
                keyList.append(key)

        # if no IP match found, find ip range/subnet. Do not use subnet if exact IP found.
        if len(keyList) == 0:
            for key in policy.keys():
                try:
                    ipObj = ip_address(mysteryDevice)
                    netObj = ip_network(key)
                    if ipObj in netObj:
                        keyList.append(key)
                except Exception as e:
                    printD("checkPolicy policy check warning: {0}".format(e))

        # if no exact IP found or range/subnet match, resort to default
        if len(keyList) == 0:
            keyList.append("default")

        for key in keyList:
            # check for "all"
            if key in policy and (policy[key]["scans"] == "all" or "all" in policy[key]["scans"]):
                allowed = True
            # check for direct match
            elif key in policy and (helper.compareSingle(policy[key]["scans"], scanOrCategoryName) or helper.singleInList(scanOrCategoryName, policy[key]["scans"])):
                allowed = True
            # check if policy has a category that covers the given scanOrCategoryName in scans.json
            elif key in policy:
                for policyName in policy[key]["scans"]:
                    parent = helper.getNested(scans, policyName)
                    if parent != False:
                        child = helper.getNested(parent, scanOrCategoryName)
                        if child != False:
                            allowed = True
                            break
            if allowed:
                break

        if not allowed:
            printD("baseProcessEvidence.checkPolicy() - Scan {0} not allowed. Skipping.".format(scanOrCategoryName))

            eventTimestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S%f")
            event = {}
            event["TYPE"] = ["IDENTIFICATION"]
            event["TARGET_IPADDR"] = [mysteryDevice]
            event["SIGNATURE"] = [scanOrCategoryName]
            event["STATUS"] = ["Blocked"]
            event["INFO"] = ["Scan {0} not allowed via policy for IP {1}".format(scanOrCategoryName, mysteryDevice)]
            #self.DBManager.insert(EVENTS_DB_FILE, eventTimestamp, event)
            self.DBManagerNew.insert(NEW_EVENTS_DB_FILE, mysteryDevice, event, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Scan Blocked - Policy")

            #self.publish_internal("internal", {"TARGET_IPADDR": mysteryDevice, scanOrCategoryName: "No"})
            self.resultsDict["internal"].append({"TARGET_IPADDR": mysteryDevice, scanOrCategoryName: "No"})
        return allowed

    ##########################################################
    # checkSent()
    # Check sent requests to see if it was already sent
    ##########################################################
    def checkSent(self, mysteryDevice, scanName):
        #printD("BaseMysteryEvidenceProcessor.checkSent()")
        scanSent = False
        #mysteryEvidence = dbManager.select(E_DB_FILE, mysteryDevice)
        allEvents = dbManagerNew.select_all(NEW_EVENTS_DB_FILE, mysteryDevice)

        activeScansSent = []
        if "ACTIVE_SCANS_SENT" in allEvents.keys():
            activeScansSent = allEvents["ACTIVE_SCANS_SENT"]

        if helper.singleInList(scanName, activeScansSent) != False:
            scanSent = True

        if scanSent == True:
            printD("ProcessIPEngine.checkSent() - ip: {0}, WARNING: scan {1} already sent".format(mysteryDevice, scanName))

        else:
            printD("ProcessIPEngine.checkSent() - ip: {0}, allowing {1}, not in {2}".format(mysteryDevice, scanName, activeScansSent))

        return scanSent

    #######################################################
    # getAllScansUnder
    #######################################################
    def getAllScansUnder(self, scansList, myDict):
        for key in myDict.keys():
            if isinstance(myDict[key], dict):
                if "PARAMS" in myDict[key].keys():
                    item = myDict[key]
                    item["PARAMS"]["SCAN_NAME"] = key
                    scansList.append(item)
                else:
                    self.getAllScansUnder(scansList, myDict[key])

    ##########################################################
    # getScan(scanOrCategoryName, vendor)
    # checks if policy allows it
    # returns either scan dict or category dict containing scans
    ##########################################################
    def getScan(self, scanOrCategoryName, mysteryDevice, **kwargs):
        #printD("BaseMysteryEvidenceProcessor.getScan()")
        scanOrCategory = "NA"

        fr = open("{0}scans.json".format(scans_path), "r", encoding="utf-8")
        scansDict = json.loads(fr.read())
        fr.close()

        # check policy
        allowed = self.checkPolicy(mysteryDevice, scanOrCategoryName)

        if allowed:
            scanOrCategory = helper.getNested(scansDict, scanOrCategoryName)
            if scanOrCategory == False:
                scanOrCategory = "NA"

        printD("baseProcessEvidence.getScan() - ip: {0}, scanOrCategoryName: {1}, scanOrCategory: {2}".format(mysteryDevice, scanOrCategoryName, scanOrCategory))
        return scanOrCategory

    def getScanWithoutPolicyCheck(self, scanOrCategoryName, mysteryDevice, mysteryEvidence, **kwargs):
        #printD("BaseMysteryEvidenceProcessor.getScan()")
        scanOrCategory = "NA"

        fr = open("{0}scans.json".format(scans_path), "r", encoding="utf-8")
        scansDict = json.loads(fr.read())
        fr.close()

        scanOrCategory = helper.getNested(scansDict, scanOrCategoryName)
        if scanOrCategory == False:
            scanOrCategory = "NA"

        printD("baseProcessEvidence.getScan() - ip: {0}, scanOrCategoryName: {1}, scanOrCategory: {2}".format(mysteryDevice, scanOrCategoryName, scanOrCategory))
        return scanOrCategory

    ##########
    #
    ##########
    def getCreds(self, mysteryDevice):
        creds = []

        fr = open("credsSafe", "rb")
        credsSafe = fr.read()
        fr.close()

        cipher_suite = Fernet(credsSafe)

        fr = open("{0}creds.json".format(scans_path), "r", encoding="utf-8")
        credsDict = json.loads(fr.read())
        fr.close()

        if mysteryDevice in credsDict.keys():
            username = credsDict[mysteryDevice]["DEFAULT_CREDS"][0]
            encrypted_password_str = credsDict[mysteryDevice]["DEFAULT_CREDS"][1]
            encrypted_password_b = encrypted_password_str.encode()
            decrypted_password_b = cipher_suite.decrypt(encrypted_password_b)
            decrypted_password_str = decrypted_password_b.decode()
            creds = [username, decrypted_password_str]

        return creds

    ##########################################################
    # getScanParams
    # fill scan object with params from evidence and return
    ##########################################################
    def getScanParams(self, scan, mysteryDevice, **kwargs):
        #printD("BaseMysteryEvidenceProcessor.getScanParams()")
        mysteryEvidence = dbManagerNew.select_all(NEW_E_DB_FILE, mysteryDevice)

        for param in scan["PARAMS"].keys():
            if param != "SCAN_NAME" and param != "DEFAULT_CREDS":
                paramKey = helper.singleInList(param, mysteryEvidence.keys())
                if paramKey != False:
                    scan["PARAMS"][param] = mysteryEvidence[paramKey][0]
                elif scan["PARAMS"][param] == "":
                    printD("ProcessIPEngine.getScanParams() WARNING - param {0} not available for scan {1}... {2}".format(param, scan["PARAMS"]["SCAN_NAME"], scan))
                    
                    eventTimestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S%f")
                    event = {}
                    event["TYPE"] = ["IDENTIFICATION"]
                    event["TARGET_IPADDR"] = [mysteryDevice]
                    event["SIGNATURE"] = [scan["PARAMS"]["SCAN_NAME"]]
                    event["STATUS"] = ["Failed"]
                    event["INFO"] = ["Could not grab params for scan {0} from IP {1} evidence.".format(scan["PARAMS"]["SCAN_NAME"], mysteryDevice)]
                    #self.DBManager.insert(EVENTS_DB_FILE, eventTimestamp, event)
                    self.DBManagerNew.insert(NEW_EVENTS_DB_FILE, mysteryDevice, event, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Scan Failed - Parameter Lookup")

                    scan = "NA"
                    break
            elif param == "DEFAULT_CREDS":
                creds = self.getCreds(mysteryDevice)
                if creds != []:
                    scan["PARAMS"][param] = creds
                else:
                    printD("ProcessIPEngine.getScanParams() ERROR - param {0} missing in policy for {1}".format(param, mysteryDevice))
                    
                    eventTimestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S%f")
                    event = {}
                    event["TYPE"] = ["IDENTIFICATION"]
                    event["TARGET_IPADDR"] = [mysteryDevice]
                    event["SIGNATURE"] = [scan["PARAMS"]["SCAN_NAME"]]
                    event["STATUS"] = ["Failed"]
                    event["INFO"] = ["Could not grab default creds for scan {0} from IP {1} policy.".format(scan["PARAMS"]["SCAN_NAME"], mysteryDevice)]
                    #self.DBManager.insert(EVENTS_DB_FILE, eventTimestamp, event)                    
                    self.DBManagerNew.insert(NEW_EVENTS_DB_FILE, mysteryDevice, event, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Scan Failed - Credential Lookup")

                    scan = "NA"
                    break

        return scan

    ##########################################################
    # determineScan()
    # this is the function that gets called in order to determine what unknown data would be impactful for the inference operation. 
    # This data will then be used to determine which scan should be fired off. 
    ##########################################################
    def determineScan(self, mysteryDevice, **kwargs):
        #printD("BaseMysteryEvidenceProcessor.determineScan()")
        pass

    ##########################################################
    # runDecisionTree()
    # Calls decision tree to receive an action name based on evidence/profile
    ##########################################################
    def runDecisionTree(self, mysteryDevice, mysteryEvidence):
        #printD("BaseMysteryEvidenceProcessor.runDecisionTree()")
        pass


    ##########################################################
    # requestScan()
    ##########################################################
    def requestScan(self, mysteryDevice, scan, siteName):
        #printD("baseProcessEvidence.requestScan()")
        eventTimestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S%f")
        event = {}
        event["TYPE"] = ["IDENTIFICATION"]
        event["TARGET_IPADDR"] = [mysteryDevice]
        event["SIGNATURE"] = [scan["PARAMS"]["SCAN_NAME"]]
        event["STATUS"] = ["Sent"]
        event["INFO"] = ["Awaiting response."]
        #self.DBManager.insert(EVENTS_DB_FILE, eventTimestamp, event)
        self.DBManagerNew.insert(NEW_EVENTS_DB_FILE, mysteryDevice, event, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Active Request")

        #self.publish_internal("internal", {"TARGET_IPADDR": mysteryDevice, scan["PARAMS"]["SCAN_NAME"]: "yes"})
        self.resultsDict["internal"].append({"TARGET_IPADDR": mysteryDevice, scan["PARAMS"]["SCAN_NAME"]: "yes"})

        #printD("baseProcessEvidence.requestScan() - ip: {0}, sending request: {1}, {2}, sentScans: {3}".format(mysteryDevice, scan["PARAMS"], siteName, dbManager.select(E_DB_FILE, mysteryDevice).get("ACTIVE_SCANS_SENT", [])))
        printD("baseProcessEvidence.requestScan() - ip: {0}, sending request: {1}, {2}, sentScans: {3}".format(mysteryDevice, scan["PARAMS"], siteName, dbManagerNew.select_all(NEW_EVENTS_DB_FILE, mysteryDevice).get("ACTIVE_SCANS_SENT", [])))
        
        #self.DBManager.insert(E_DB_FILE, mysteryDevice, {"ACTIVE_SCANS_SENT": [scan["PARAMS"]["SCAN_NAME"]]})
        self.DBManagerNew.insert(NEW_EVENTS_DB_FILE, mysteryDevice, {"ACTIVE_SCANS_SENT": [scan["PARAMS"]["SCAN_NAME"]]}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Active Request")

        #self.publish_request("active.requests.{0}".format(siteName), scan["PARAMS"])
        self.resultsDict["external"].append({"ACTIVE_REQUEST_STRING": "active.requests.{0}".format(siteName), "SCAN": scan["PARAMS"]})
