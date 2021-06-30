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

import multiprocessing

import logging
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
from math import *
from io import open
import gevent
from gevent.subprocess import Popen, PIPE
from gevent import socket as gsock
import time
import datetime
import subprocess
import multiprocessing

from ..common.actor import Actor
from ssasse_platform.InferenceEngine.baseProcessEvidence import BaseMysteryEvidenceProcessor

try:
    import yaml
except ImportError:
    raise RuntimeError('PyYAML must be installed before running this script ')

import sqlite3
import json
from .Databases import dbManager
from .Databases import dbManagerNew

#from . import decision_tree_design
from ssasse_platform.InferenceEngine.deviceDecisionTree import DeviceDecisionTree
from . import helper

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

network_probes = {
    'SEL': {
        'relay': ['ftp', 'telnet', 'http', 'https'], 
        'rtu': ['database', 'ftp', 'telnet', 'http', 'https'],
        'port_server': []},
    'GE': {
        'relay': ['ftp', 'telnet', 'http', 'https'],
        'rtu': ['ftp', 'telnet', 'http', 'https'],
        'port_server': []},
    'SCHNEIDER': {
        'relay': ['http'],
        'rtu': [],
        'port_server': []},
    'REDLIONINC': {
        'relay': [],
        'rtu': [],
        'port_server': []},
    'EMERSON': {
        'relay': [],
        'rtu': [],
        'port_server': []},
    'LANTRONIX': {
        'relay': [],
        'rtu': [],
        'port_server': []}
}

known_scada_vendors = ["GE", "SEL", "SCHNEIDER", "EMERSON", "REDLIONINC", "SIEMENS", "LANTRONIX"]
printD(type(known_scada_vendors))

class IpIdentifier(BaseMysteryEvidenceProcessor):
    def __init__(self, config, DBManager, DBManagerNew, rmq_connection):
        printD("IpIdentifier.__init__()")
        super(IpIdentifier, self).__init__(config, DBManager, DBManagerNew, rmq_connection)


    def scanCategoryDecision(self, mysteryDevice, categoryName, scanCategory):
        decision = "NA"
        mysteryEvidence = dbManagerNew.select_all(NEW_E_DB_FILE, mysteryDevice)

        printD("scanCategoryDecision() - ip: {0}, categoryName: {1}, scanCategory: {2}".format(mysteryDevice, categoryName, scanCategory))

        printD("scanCategoryDecision() - mysteryEvidence: {0}, scanCategory: {1}".format(mysteryEvidence, scanCategory))

        if categoryName == "config_scan":
            if "VENDOR" in mysteryEvidence.keys():
                vendorKey = helper.singleInList(mysteryEvidence["VENDOR"][0], scanCategory.keys())
                if vendorKey:
                    vendorCategory = scanCategory[vendorKey]
                    scanDict = {}
                    for scanName,val in vendorCategory.items():
                        if "identification" in val["TYPE"]:
                            scanDict[scanName] = val

                    if len(scanDict.keys()) > 1:
                        if "DEVICE_TYPE" in mysteryEvidence.keys():
                            deviceType = mysteryEvidence["DEVICE_TYPE"][0]
                            for scanName,val in scanDict.items():
                                if not self.checkSent(mysteryDevice, scanName):
                                    if deviceType == val["DEVICE_TYPE"]:
                                        return scanName
                        else:
                            decision = "no"
                    elif len(scanDict.keys()) == 1:
                        for scanName,val in vendorCategory.items():
                            if not self.checkSent(mysteryDevice, scanName):
                                return scanName
                    else:
                        decision = "no"

            else:
                decision = "no"

        elif categoryName == "scada_scan" or categoryName == "tcp_scan":
            meProtocols = []
            if "PROTOCOLS" in mysteryEvidence.keys():
                meProtocols = mysteryEvidence["PROTOCOLS"]
            printD("scanCategoryDecision() - ip: {0}, meProtocols: {1}".format(mysteryDevice, meProtocols))
            for protocol in meProtocols:
                scanCategoryKey = helper.singleInList(protocol, scanCategory.keys())
                if scanCategoryKey:
                    protocolCategory = scanCategory[scanCategoryKey]
                    scanDict = {}
                    for scanName,val in protocolCategory.items():
                        if "identification" in val["TYPE"]:
                            if val["PRIORITY"] not in scanDict:
                                scanDict[val["PRIORITY"]] = []
                            scanDict[val["PRIORITY"]].append(scanName)

                    printD("identifyIP.scanCategoryDecision() - ip: {0}, scanDict: {1}".format(mysteryDevice, scanDict))
                    for priority in sorted(scanDict.keys()):
                        scanList = scanDict[priority]
                        for scanName in scanList:
                            if not self.checkSent(mysteryDevice, scanName):
                                return scanName

        elif categoryName == "network_scan":
            if "VENDOR" in mysteryEvidence.keys():
                meVendor = mysteryEvidence["VENDOR"][0]
                # use protocols found in evidence to prioritize scans
                if "SERVICE" in mysteryEvidence.keys():
                    meProtocols = mysteryEvidence["SERVICE"]
                    for protocol in meProtocols:
                        scanCategoryKey = helper.singleInList(protocol, scanCategory.keys())
                        if scanCategoryKey:
                            protocolCategory = scanCategory[scanCategoryKey]
                            scanDict = {}
                            for scanName,val in protocolCategory.items():
                                if "identification" in val["TYPE"]:
                                    if val["PRIORITY"] not in scanDict:
                                        scanDict[val["PRIORITY"]] = []
                                    scanDict[val["PRIORITY"]].append(scanName)

                            for priority in sorted(scanDict.keys()):
                                scanList = scanDict[priority]
                                for scanName in scanList:
                                    if not self.checkSent(mysteryDevice, scanName):
                                        return scanName

                # otherwise use network_probes to go through the protocols and try scans
                networkProbeKey = helper.singleInList(meVendor, network_probes)
                if networkProbeKey:
                    # get device type
                    deviceType = mysteryEvidence.get("DEVICE_TYPE", ['relay'])[0]
                    protocolList = network_probes[networkProbeKey][deviceType]
                    for protocol in protocolList:
                        scanCategoryKey = helper.singleInList(protocol, scanCategory.keys())
                        if scanCategoryKey:
                            protocolCategory = scanCategory[scanCategoryKey]
                            scanDict = {}
                            for scanName,val in protocolCategory.items():
                                if "identification" in val["TYPE"]:
                                    if val["PRIORITY"] not in scanDict:
                                        scanDict[val["PRIORITY"]] = []
                                    scanDict[val["PRIORITY"]].append(scanName)

                            for priority in sorted(scanDict.keys()):
                                scanList = scanDict[priority]
                                for scanName in scanList:
                                    if not self.checkSent(mysteryDevice, scanName):
                                        return scanName

        return decision

    ##########
    #
    ##########
    def decisionSimple(self, mysteryDevice):
        categoryOrder = ["OUI_Lookup", "config_scan", "scada_scan", "tcp_scan", "network_scan"]
        chosenCategory = "NA"
        scanEvidence = dbManager.select(E_DB_FILE, mysteryDevice)
        mysteryEvidence = dbManagerNew.select_all(NEW_E_DB_FILE, mysteryDevice)

        if "TARGET_MACADDR" in scanEvidence:
            if not helper.singleInList("OUI_Lookup", scanEvidence.keys()):
                chosenCategory = "OUI_Lookup"

            elif "VENDOR" in mysteryEvidence.keys() and helper.singleInList(mysteryEvidence["VENDOR"][0], known_scada_vendors) != False:
                for categoryName in categoryOrder:
                    if not helper.singleInList(categoryName, scanEvidence.keys()) and self.checkSentPerCategory(mysteryDevice, categoryName) != None and len(self.checkSentPerCategory(mysteryDevice, categoryName)) > 0:
                        chosenCategory = categoryName
                        break

        printD("identifyIP.decisionSimple() - ip: {0}, chosenScan: {1}, evidence: {2}, scanEvidence: {3}".format(mysteryDevice, chosenCategory, mysteryEvidence, scanEvidence))
        return chosenCategory


    ##########################################################
    # determineScan()
    # this is the function that gets called in order to determine what unknown data would be impactful for the inference operation. 
    # This data will then be used to determine which scan should be fired off. 
    ##########################################################
    def determineScan(self, mysteryDevice, **kwargs):
        #printD("IpIdentifier.determineScan()")
        scan = "NA"
        mysteryEvidence = dbManagerNew.select_all(NEW_E_DB_FILE, mysteryDevice)

        # Error/NA/Wait
        skips = ["NA", "Wait", "Done", False]

        # Determine scan
        decision = self.runDecisionTree(mysteryDevice, "global")

        # oui
        if decision == "OUI_Lookup":
            vendor = self.OUILookUp(mysteryEvidence["TARGET_MACADDR"][0])
            if vendor != "NA":
                #self.publish_internal("internal", {"TARGET_IPADDR": mysteryDevice, "VENDOR": vendor, decision: "yes"})
                self.resultsDict["internal"].append({"TARGET_IPADDR": mysteryDevice, "VENDOR": vendor, decision: "yes"})
            else:
                #self.publish_internal("internal", {"TARGET_IPADDR": mysteryDevice, "VENDOR": vendor, decision: "no"})
                self.resultsDict["internal"].append({"TARGET_IPADDR": mysteryDevice, "VENDOR": vendor, decision: "no"})
            return "NA"

        # Vendor tree
        elif decision == "Vendor_tree":
            decision = self.runDecisionTree(mysteryDevice, "vendor")

        # Model tree
        # if unknown, don't try to find firmware
        elif decision == "Model_tree":
            decision = self.runDecisionTree(mysteryDevice, "model")

        # if unknown, handle logic for having ran out of options
        # if global = done, identified.
        # if vendor = done, found a model, transition to model type. - set model to yes in prepareEvidence.  if unknown, set model to no. 
        # if model = done, found firmware, done, either quit here or feed to global. if firmware present, set to yes/true in prepareEvidence
        # if unknown for any, exit
        if decision == "Unknown":
            decision = self.decisionSimple(mysteryDevice)

        if decision in skips:
            printD("identifyIP.determineScan() - Scan non-decision: {0}".format(decision))

        # valid scan/category
        else:
            # decision should be either individual scan name or category (config_scan, etc)
            scanOrCategory = self.getScan(decision, mysteryDevice, **kwargs)
            #printD("determineScan() - ip: {0}, scanOrCategory: {1}, decision: {2}".format(mysteryDevice, scanOrCategory, decision))
            printD("determineScan() - ip: {0}, decision: {1}".format(mysteryDevice, decision))

            # if decision was specific scan
            if scanOrCategory != "NA" and "PARAMS" in scanOrCategory.keys():
                scan = scanOrCategory
                printD("SN: getScan: {}".format(scan))
                scan["PARAMS"]["SCAN_NAME"] = decision

            # category. get all scans under that category 
            elif scanOrCategory != "NA":
                scanName = self.scanCategoryDecision(mysteryDevice, decision, scanOrCategory)
                printD("identifyIP.scanCategoryDecision - ip: {0}, scanCategoryDecision: {1}".format(mysteryDevice, scanName))

                # ex when config_scan and multiple scans, with no device_type
                if scanName == "no":
                    #self.publish_internal("internal", {"TARGET_IPADDR": mysteryDevice, decision: "no"})
                    self.resultsDict["internal"].append({"TARGET_IPADDR": mysteryDevice, decision: "no"})
                    scan = "NA"

                elif scanName == "NA":
                    scan = "NA"

                else:
                    # go get params (empty params) 
                    scan = self.getScan(scanName, mysteryDevice, **kwargs)
                    printD("SN: getScan: {}".format(scan))
                    scan["PARAMS"]["SCAN_NAME"] = scanName

            # check sent and fill params
            if scan != "NA" and not self.checkSent(mysteryDevice, scan["PARAMS"]["SCAN_NAME"]):
                scan = self.getScanParams(scan, mysteryDevice, **kwargs)
            else:
                scan = "NA"

        return scan

    #########################################################
    # checkSentPerCategory()
    # Check sent requests in an entire category to see 
    #  if all scans in that category sent. If not, return 
    #  list of scans not sent. 
    ##########################################################
    def checkSentPerCategory(self, mysteryDevice, categoryName):
        #printD("BaseMysteryEvidenceProcessor.checkSent()")
        scanSent = False

        scanCategory = self.getScan(categoryName, mysteryDevice)
        # recursively parse scans json to look for keys/scan names

        protocolList = ["dnp3", "modbus", "rocplus"]
        scansList = []

        mysteryEvidence = dbManager.select(E_DB_FILE, mysteryDevice)

        if categoryName == "config_scan":
            if "VENDOR" in mysteryEvidence.keys():
                meVendor = mysteryEvidence["VENDOR"][0]
                scanCategoryKey = helper.singleInList(meVendor, scanCategory.keys())
                vendorCategory = scanCategory[scanCategoryKey]
                for scanName,val in vendorCategory.items():
                    if "identification" in val["TYPE"]:
                        scansList.append(scanName)

        elif categoryName == "tcp_scan" or categoryName == "scada_scan":
            for protocol in protocolList:
                if "PROTOCOLS" in mysteryEvidence.keys():
                    meProtocol = helper.singleInList(protocol, mysteryEvidence["PROTOCOLS"])
                    if meProtocol:
                        scanCategoryKey = helper.singleInList(meProtocol, scanCategory.keys())
                        if scanCategoryKey:
                            protocolCategory = scanCategory[scanCategoryKey]
                            for scanName,val in protocolCategory.items():
                                if "identification" in val["TYPE"]:
                                    scansList.append(scanName)
                else:
                    pass

        elif categoryName == "network_scan":
            if "VENDOR" in mysteryEvidence.keys():
                meVendor = mysteryEvidence["VENDOR"][0]

                networkProbeKey = helper.singleInList(meVendor, network_probes.keys())
                # get device type
                deviceType = mysteryEvidence.get("DEVICE_TYPE", ['relay'])[0]
                if networkProbeKey:
                    protocolList = network_probes[networkProbeKey][deviceType]
                    for protocol in protocolList:
                        scanCategoryKey = helper.singleInList(protocol, scanCategory.keys())
                        if scanCategoryKey:
                            protocolCategory = scanCategory[scanCategoryKey]
                            for scanName,val in protocolCategory.items():
                                if "identification" in val["TYPE"]:
                                    scansList.append(scanName)

        scansNotSent = None

        if len(scansList) != 0:
            scansNotSent = set()
            for scanName in scansList:
                if not self.checkSent(mysteryDevice, scanName):
                    scansNotSent.add(scanName)

        printD("identifyIP.checkSentPerCategory() - ip: {0}, categoryName: {1}, scansNotSent: {2}".format(mysteryDevice, categoryName, scansNotSent))
        return scansNotSent

    ######################################################
    # prepareEvidence
    ######################################################
    def prepareEvidence(self, mysteryDevice, treeType, modelDecision=None, firmwareDecision=None):
        preparedEvidence = {}
        categoriesList = []
        keysList = []

        mysteryEvidence = dbManagerNew.select_all(NEW_E_DB_FILE, mysteryDevice)
        scanEvidence = dbManager.select(E_DB_FILE, mysteryDevice)

        if treeType == "global":
            categoriesList = ["tcp_scan"]

            if "TARGET_MACADDR" in mysteryEvidence.keys():
                preparedEvidence["MAC"] = "yes"
            if "OUI_LOOKUP" in mysteryEvidence.keys():
                preparedEvidence["OUILOOKUP"] = "yes"
            if "PROTOCOLS" in mysteryEvidence.keys():
                preparedEvidence["Protocol"] = mysteryEvidence["PROTOCOLS"][0].lower()

            if "VENDOR" in mysteryEvidence.keys():
                if helper.singleInList(mysteryEvidence["VENDOR"][0], known_scada_vendors):
                    preparedEvidence["Vendor"] = "yes"
                else:
                    preparedEvidence["Vendor"] = "no"

            if "MODEL" in mysteryEvidence.keys():
                preparedEvidence["Model"] = "yes"
            elif modelDecision == "Unknown":
                preparedEvidence["Model"] = "no"

            if "FIRMWARE_ID" in mysteryEvidence.keys():
                preparedEvidence["Firmware"] = "yes"
            elif firmwareDecision == "Unknown":
                preparedEvidence["Firmware"] = "no"

            # todo: logic for tcp_scan, READ_ATTR, similar to config_scan

        elif treeType == "vendor":
            # config_scan set to yes when all scans under that category have been exhausted, same with SCADA/TCP
            # if policy does not allow, set to no 
            # else, it is empty (when some have been triggered but not all, and it is allowed via policy)
            categoriesList = ["config_scan","scada_scan","tcp_scan","network_scan"]

            if "PROTOCOLS" in mysteryEvidence.keys():
                preparedEvidence["Protocol"] = "available"

            if "SERVICES" in mysteryEvidence.keys():
                preparedEvidence["Services"] = "available"

            if "MODEL" in mysteryEvidence.keys():
                preparedEvidence["Model"] = "yes"
            elif modelDecision == "Unknown":
                preparedEvidence["Model"] = "no"

        elif treeType == "model":
            categoriesList = ["config_scan","network_scan"]

            if "MODEL" in mysteryEvidence.keys():
                preparedEvidence["Model"] = mysteryEvidence["MODEL"][0].lower()

            if "FIRMWARE_ID" in mysteryEvidence.keys():
                preparedEvidence["Firmware"] = "yes"

        for categoryName in categoriesList:
            if not self.checkPolicy(mysteryDevice, categoryName):
                printD("identifyIP.prepareEvidence() - ip: {0}, category {1} set to no because of policy".format(mysteryDevice, categoryName))
                preparedEvidence[categoryName] = "no"
            elif helper.singleInList(categoryName, scanEvidence.keys()) and scanEvidence[helper.singleInList(categoryName, scanEvidence.keys())][0] == "no":
                if categoryName == "config_scan":
                    if "DEVICE_TYPE" in mysteryEvidence.keys():
                        preparedEvidence[categoryName] = "empty"
                    else:
                        preparedEvidence[categoryName] = "no"
                else:
                    printD("identifyIP.prepareEvidence() - ip: {0}, category {1} set to no because of previous evidence".format(mysteryDevice, categoryName))
                    preparedEvidence[categoryName] = "no"
            else:
                printD("identifyIP.prepareEvidence() - ip: {0}, category {1} allowed".format(mysteryDevice, categoryName))
                scansNotSent = self.checkSentPerCategory(mysteryDevice, categoryName)
                if scansNotSent == None:
                    preparedEvidence[categoryName] = "no"
                elif len(scansNotSent) > 0:
                    preparedEvidence[categoryName] = "empty"
                else:
                    preparedEvidence[categoryName] = "yes"
        printD("identifyIP.prepareEvidence() IP: {}, prep evidence: {}".format(mysteryDevice, preparedEvidence))
        return preparedEvidence

    ##########################################################
    # runDecisionTree()
    # Calls decision tree to receive an action name based on 
    # evidence/profile
    ##########################################################
    def runDecisionTree(self, mysteryDevice, treeType, modelDecision=None, firmwareDecision=None):
        #printD("IpIdentifier.runDecisionTree()")
        #decision = decisionSimple.decision(mysteryEvidence)

        profiles = {}
        decisionTree = DeviceDecisionTree(profiles, treeType)

        preparedEvidence = self.prepareEvidence(mysteryDevice, treeType, modelDecision, firmwareDecision)
        decision = decisionTree.predict(preparedEvidence)

        printD("ProcessIPEngine.runDecisionTree() - ip: {0}, preparedEvidence: {1}, decision: {2}, treeType: {3}".format(mysteryDevice, preparedEvidence, decision, treeType))
        return decision

    ##########################################################
    # processIP()
    ##########################################################
    def identifyIP(self, mysteryDevice, resultsDict, rmq_socket):
        printD("IpIdentifier.processIP()")
        # rmq_socket.detach()
        file_no = rmq_socket.fileno()
        import os
        os.close(file_no)

        self.infer(mysteryDevice)

        resultsDict["internal"] = self.resultsDict["internal"]
        resultsDict["external"] = self.resultsDict["external"]
        printD("MP resultsDict: {}".format(resultsDict))
        return resultsDict
