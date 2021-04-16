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

'''
Identify vulnerabilities in ports and services it is running based on the evidence
'''

import logging
import sys
if sys.version_info[0] >= 3:
    unicode = str

import os
import json
from math import *
from io import open
import subprocess
import multiprocessing
import datetime

from ssasse_platform.InferenceEngine.baseProcessEvidence import BaseMysteryEvidenceProcessor

from .Databases import dbManager
#from . import service_decision_tree
from ssasse_platform.InferenceEngine.serviceDecisionTree import ServicesDecisionTree
from . import helper

logger = logging.getLogger(__name__)

DEBUG = True
def printD(m):
    if DEBUG:
        logger.debug(m)

# Database files
E_DB_FILE = "e_db.sqlite" # evidence
D_DB_FILE = "d_db.sqlite" # devices
V_DB_FILE = "v_db.sqlite" # vendors
VULN_DB_FILE = "vuln_db.sqlite" # vulnerabilities
EVENTS_DB_FILE = "events_db.sqlite" # events

# Paths
database_path = "ssasse_platform/InferenceEngine/Databases/"
scans_path = "ssasse_platform/InferenceEngine/Scans/"
vendor_profiles_path = "ssasse_platform/InferenceEngine/Profiles/Vendors"

timelineStrings = {
    "PORT_OPEN": "Device profile suggests Service {} runs on Port {}. Port is open.",
    "PORT_NOT_OPEN": "Device profile suggests Service {} runs on Port {}. Port is not open.",
    "SERVICE_NOT_RUNNING": "{} on PORT {} not running.",
    "SERVICE_IS_RUNNING": "{} on PORT {} is running. No further action can be made.",
    "ANONYMOUS_ACCESS": "{} on PORT {} allows anonymous connection access",
    "DEFAULT_ACCESS": "{} on PORT {} uses default credentials",
    "AUTHENTICATED_ACCESS": "{} on PORT: {} uses non default credentials.",
    "DNP3_ALL_MASTER_ACCESS": "{} protocol is running on PORT {}. \
Device responds to scanner IP address as DNP3 master. This could indicate that the device is open to any DNP3 master. \
You may want to limit the IP addresses that can act as DNP3 masters for this device.",
    "DNP3_SINGLE_MASTER_ACCESS": "{} protocol is running on PORT {}. \
Device is lockdown to single DNP3 master. \
    Configuration looks correct."
}

vulnerabilityIDMapping = {
    "PORT_OPEN": {
        "DESCRIPTION": "Device profile suggests Service {} runs on Port {}. Port is open.",
        "SEVERITY": "Info",
        "SUGGESTIONS": ""
    },
    "PORT_NOT_OPEN": {
        "DESCRIPTION": "Device profile suggests Service {} runs on Port {}. Port is not open.",
        "SEVERITY": "Info",
        "SUGGESTIONS": ""
    },
    "ANONYMOUS_ACCESS": {
        "DESCRIPTION": "{} service on port {} allows anonymous connection access.",
        "SEVERITY": "High",
        "SUGGESTIONS": "Please add autentication to service."
    },
    "DEFAULT_ACCESS": {
        "DESCRIPTION": "{} service on port {} uses default credentials.",
        "SEVERITY": "Medium",
        "SUGGESTIONS": "Please change to non-default credentials."
    },
    "DNP3_ALL_MASTER_ACCESS": {
        "DESCRIPTION": "{} protocol is running on PORT {}. Device responds to scanner IP address as DNP3 master. This could indicate that the device is open to any DNP3 master.",
        "SEVERITY": "Medium",
        "SUGGESTIONS": "You may want to limit the IP addresses that can act as DNP3 masters for this device."
    },
    "SERVICE_NOT_RUNNING": {
        "DESCRIPTION": "Service {} on open port {} not running.",
        "SEVERITY": "Low",
        "SUGGESTIONS": "You may want to close unused port."
    },
    "SERVICE_IS_RUNNING": {
        "DESCRIPTION": "Service {} on open port {} is running.",
        "SEVERITY": "Info",
        "SUGGESTIONS": "No further action can be made."
    },
    "AUTHENTICATED_ACCESS": {
        "DESCRIPTION": "Service {} on PORT: {} uses non default credentials.",
        "SEVERITY": "Info",
        "SUGGESTIONS": ""
    },
    "DNP3_SINGLE_MASTER_ACCESS": {
        "DESCRIPTION": "{} protocol is running on PORT {}. Device is lockdown to single DNP3 master. Configuration looks correct.",
        "SEVERITY": "Info",
        "SUGGESTIONS": ""
    }
}

serviceMapping = {
    "ISOTSAP": "IEC 61850 MMS/ Siemens S7",
    "MBAP": "MODBUS",
    "SIXTRAK": "Protocol for Control Wave products from SixNET",
    "PULSEAUDIO": "IEEE C37.118",
    "REMOTEANYTHING": "Possibly ROCPLUS"
}

vulnerability_decisions = ["SERVICE_NOT_RUNNING", "SERVICE_IS_RUNNING", "ANONYMOUS_ACCESS", 
"DEFAULT_ACCESS", "AUTHENTICATED_ACCESS", "DNP3_ALL_MASTER_ACCESS", 
"DNP3_SINGLE_MASTER_ACCESS"]

class ServiceProcessor(BaseMysteryEvidenceProcessor):
    def __init__(self, config, DBManager, rmq_connection):
        printD("ServiceProcessor.__init__()")
        super(ServiceProcessor, self).__init__(config, DBManager, rmq_connection)
        self.port = None
        self.processingServices = {}
        self.identifiedVulnerabilities = {}
        self.processStarted = dict()
        self.serviceInfo = dict()
        self.nmap = None

    ##########################################################
    # getScanParams
    # fill scan object with params from evidence and return
    ##########################################################
    def getScanParams(self, scan, mysteryDevice, mysteryEvidence, **kwargs):
        port = kwargs['port']

        for param in scan["PARAMS"].keys():
            if param == 'TARGET_IPADDR':
                scan["PARAMS"][param] = mysteryEvidence[param][0]
            elif param == 'TARGET_PORTS':
                if scan["PARAMS"]['SCAN_NAME'] == 'nmap_service_scan':
                    if isinstance(port, list):
                        portString = ','.join(port)
                        scan["PARAMS"][param] = portString
                        printD("SN: TARGET_PORTS string: {}".format(portString))
                    else:
                        scan["PARAMS"][param] = port
                else:
                    scan["PARAMS"][param] = port
            elif param == 'TARGET_PORT':
                scan["PARAMS"][param] = port
            elif param == 'VENDOR':
                scan["PARAMS"][param] = mysteryEvidence[param][0]
            elif param == 'DNP3_PORT':
                scan["PARAMS"][param] = mysteryEvidence[param][0]
            elif param == 'DNP3_MASTER_ID':
                scan["PARAMS"][param] = mysteryEvidence[param][0]
            elif param == 'DNP3_SLAVE_ID':
                scan["PARAMS"][param] = mysteryEvidence[param][0]
            elif param == 'DEFAULT_CREDS':
                # Read from scans.json
                vendorPath = "{0}/{1}.json".format(vendor_profiles_path, 
                        mysteryEvidence["VENDOR"][0].upper())
                fr = open(vendorPath, "r", encoding="utf-8")
                vendorConfig = json.loads(fr.read())
                fr.close()
                services = vendorConfig.get("SERVICES", {})
                scanName = scan["PARAMS"]['SCAN_NAME'] 
                s = scanName.split('_')[0]
                service_params = services.get(s, {})
                if service_params:
                   try:
                       scan["PARAMS"][param] = service_params[param]
                   except KeyError as e:
                        pass
            elif param == "SCAN_NAME":
                pass
            else:
                printD("ProcessIPEngine.getScanParams() ERROR - params not available for scan {0}, {1}".format(scan["PARAMS"]["SCAN_NAME"], param))
                
                eventTimestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S%f")
                event = {}
                event["TYPE"] = ["VULNERABILITY"]
                event["TARGET_IPADDR"] = [mysteryDevice]
                event["SIGNATURE"] = [scan["PARAMS"]["SCAN_NAME"]]
                event["STATUS"] = ["Failed"]
                event["INFO"] = ["Could not grab params for scan {0} from IP {1} evidence.".format(scan["PARAMS"]["SCAN_NAME"], mysteryDevice)]
                self.DBManager.insert(EVENTS_DB_FILE, eventTimestamp, event)

                scan = "NA"
                break
        printD("Scan parameters: {}".format(scan))
        return scan

    ##########################################################
    # checkSent()
    # Check sent requests to see if it was already sent
    ##########################################################
#    def checkSent(self, mysteryDevice, scanName):
        #printD("BaseMysteryEvidenceProcessor.checkSent()")
#        scanSent = False

        #mysteryEvidence = dbManager.select(E_DB_FILE, mysteryDevice)
#        if helper.singleInList(scanName, self.activeScansSent) != False:
#            scanSent = True

#        if scanSent == True:
#            printD("ProcessIPEngine.checkSent() - ERROR: scan {0} already sent for {1}".format(scanName, mysteryDevice))
            
            #self.publishLock.acquire()
#            self.publish_internal("internal", {"TARGET_IPADDR": mysteryDevice, scanName: "Yes"})
            #self.publishLock.release()

#        return scanSent
    
    ##########################################################
    # determineScan()
    # this is the function that gets called in order to determine what unknown data would be impactful for the inference operation. 
    # This data will then be used to determine which scan should be fired off. 
    ##########################################################
    def determineScan(self, deviceIP, mysteryEvidence, **kwargs):
        port = kwargs['port']
        #self.counter += 1
        #printD("New evidence to determineScan: {}".format(mysteryEvidence))
        evidence = {}
        if self.nmap is not None and self.nmap == "done":
            evidence = self.prepareEvidence(deviceIP, port, mysteryEvidence)
        scan = "NA"

        printD("SN: Prepared evidence for decision tree: {}, self.nmap: {}".format(evidence, self.nmap))
        # Determine scan TYPE
        decision = self.runDecisionTree(deviceIP, evidence)
        printD("SN: Prepared service decision tree decision: {}, {}, {}, {}".format(deviceIP, port, decision, type(decision)))
        
        if decision not in ["nmap_service_scan", "PORT_NOT_OPEN"]:
            vulnDict = vulnerabilityIDMapping["PORT_OPEN"]
            vulnDict["DESCRIPTION"] = vulnDict["DESCRIPTION"].format(self.service, port)
            self.DBManager.insertVulnerabilityTableEntry(E_DB_FILE, VULN_DB_FILE, deviceIP, vulnDict)

        # valid scan actions, 
        if decision in ["nmap_service_scan", "FTP_default_cred_Check", "TELNET_default_cred_Check", "HTTP_default_credential_Check", "dnp3_request_link_status"]:
            allowed = self.checkPolicy(deviceIP, decision)
            if allowed and "VENDOR" in mysteryEvidence:
                scan = self.getScan(decision, deviceIP, mysteryEvidence, **kwargs)
                scan["PARAMS"]["SCAN_NAME"] = decision 
#                printD("SN: getScan: {}".format(scan))
            else:
                scan = "NA"

            if scan != "NA":
                scan = self.getScanParams(scan, deviceIP, mysteryEvidence, **kwargs)
            else:
                #self.publish_internal("internal", {"TARGET_IPADDR": deviceIP, decision: "No"})
                self.resultsDict["internal"].append({"TARGET_IPADDR": deviceIP, decision: "No"})

            if scan != "NA":
                sent = self.checkSent(deviceIP, mysteryEvidence, scan["PARAMS"]["SCAN_NAME"])
                printD("SN: checkSent {}".format(sent))

                if sent:
                    scan = "NA"
        elif decision in ["PORT_NOT_OPEN"]:
            self.identified = "y"
            
            vulnDict = vulnerabilityIDMapping[decision]
            vulnDict["DESCRIPTION"] = vulnDict["DESCRIPTION"].format(self.service, port)
            self.DBManager.insertVulnerabilityTableEntry(E_DB_FILE, VULN_DB_FILE, deviceIP, vulnDict)

        elif decision in vulnerability_decisions:
            if evidence["SERVICE_RUNNING"] == "dnp":
                if decision == "DEFAULT_ACCESS":
                    decision = "DNP3_ALL_MASTER_ACCESS"
                elif decision == "ANONYMOUS_ACCESS":
                    decision = "DNP3_SINGLE_MASTER_ACCESS"
            printD("Hit vulnerabilities decision: {}, IP: {}, Port: {}".format(decision, deviceIP, port))
            service = evidence["SERVICE_RUNNING"].upper()
            # Some of the SCADA protocols returned from nmap scans have to be 
            # interpreted correctly
            service = serviceMapping.get(service, service)
            self.identified = "y"
            
            vulnDict = vulnerabilityIDMapping[decision]
            vulnDict["DESCRIPTION"] = vulnDict["DESCRIPTION"].format(service, port)
            self.DBManager.insertVulnerabilityTableEntry(E_DB_FILE, VULN_DB_FILE, deviceIP, vulnDict)

        #Error
        elif decision == "NA":
            pass

        # If scan is a GO, add to events DB
        if scan != "NA":
            eventTimestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S%f")
            event = {}
            event["TYPE"] = ["VULNERABILITY"]
            event["TARGET_IPADDR"] = [deviceIP]
            event["SIGNATURE"] = ["{} on port {}".format(scan["PARAMS"]["SCAN_NAME"], port)]
            event["STATUS"] = ["Sent"]
            event["INFO"] = ["Awaiting response."]
            self.DBManager.insert(EVENTS_DB_FILE, eventTimestamp, event)
            #self.publish_internal("internal", {"TARGET_IPADDR": deviceIP, decision: "Yes"})
            self.resultsDict["internal"].append({"TARGET_IPADDR": deviceIP, decision: "yes"})

        #printD("determineScan END addIdentifiedVulnerabilities: {}".format(self.identifiedVulnerabilities))
        return scan

    ##########################################################
    # prepareEvidence
    # prepare evidence based on port evidence
    ##########################################################
    def prepareEvidence(self, deviceIP, devicePort, mysteryEvidence):
        evidence = {}
        port_state = 'PORTS_' + devicePort + '_PORT_STATE'
        service_name = 'PORTS_' + devicePort + '_SERVICE_NAME'
        anon = None
        default_creds = None
        
        printD("prepareEvidence for : port: {}, port: {}, evidence:{}".format(deviceIP, devicePort, mysteryEvidence))

        val = mysteryEvidence.get(port_state, None)
        if val:
            if val[0] == 'open':
                evidence['PORT_OPEN'] = 'yes'
            else:
                evidence['PORT_OPEN'] = 'no'
        val = mysteryEvidence.get(service_name, None)
        if val:
            evidence['SERVICE_RUNNING'] = val[0]
            if evidence['SERVICE_RUNNING'] == 'ftp':
                anon = mysteryEvidence.get('FTP_ANONYMOUS', None)
                if anon:
                    anon = anon[0].upper()
                default_creds = mysteryEvidence.get('FTP_DEFAULT_CREDS', None)
                if default_creds:
                    default_creds = default_creds[0].upper()
            elif evidence['SERVICE_RUNNING'] == 'telnet':
                anon = mysteryEvidence.get('TELNET_NO_PASSWORD', None)
                if anon:
                    anon = anon[0].upper()
                default_creds = mysteryEvidence.get('TELNET_DEFAULT_CREDS', None)
                if default_creds:
                    default_creds = default_creds[0].upper()    
            elif evidence['SERVICE_RUNNING'] == 'http':
                anon= 'N'
                #anon = mysteryEvidence.get('HTTP_NO_PASSWORD', None)
                #if anon:
                #    anon = anon[0].upper()
                default_creds = mysteryEvidence.get('HTTP_DEFAULT_CREDS', None)
                if default_creds:
                    default_creds = default_creds[0].upper()
            elif evidence['SERVICE_RUNNING'] == 'dnp':
                anon= 'N'
                dnp3_running = mysteryEvidence.get('DNP3_COMMS', None)
                default_master = mysteryEvidence.get('RESP_TO_ANY_DNP3_MASTER', None)
                
                if dnp3_running and default_master:
                    if not dnp3_running[0]:
                        evidence['SERVICE_RUNNING'] = 'no'
                        evidence['ANONYMOUS_ACCESS'] = 'empty'
                        evidence['DEFAULT_ACCESS'] = 'empty'
                        return evidence
                    else:
                        if default_master[0] == '0':
                            default_creds = "N" #lockdown to single master id
                        else:
                            default_creds = "Y" #anyone can be master

        if anon is not None and default_creds is not None:
            if anon == "N" and default_creds == "N":
               evidence["ANONYMOUS_ACCESS"] = "no"
               evidence["DEFAULT_ACCESS"] = "no"
            elif anon == "Y" and default_creds == "N":
               evidence["ANONYMOUS_ACCESS"] = "yes"
               evidence["DEFAULT_ACCESS"] = "no"
            elif anon == "N" and default_creds == "Y":
               evidence["ANONYMOUS_ACCESS"] = "no"
               evidence["DEFAULT_ACCESS"] = "yes"
        return evidence

    ##########################################################
    # runDecisionTree()
    # Calls decision tree to receive an action name based on 
    # evidence/profile
    ##########################################################
    def runDecisionTree(self, deviceIP, mysteryEvidence):
        training_table_path = ''
        profiles = {}
        decisionTree = ServicesDecisionTree(profiles, training_table_path)
        decision = decisionTree.predict(mysteryEvidence)
        #printD("ServiceProcessor.runDecisionTree() - evidence: {0}".format(mysteryEvidence))
        printD("ServiceProcessor.runDecisionTree() - decision: {0}, IP: {1}".format(decision, deviceIP))
        return decision

    ##########################################################
    # processService()
    ##########################################################
    def processService(self, deviceIP, devicePort, service, resultsDict, rmq_socket):
 #       self.activeScanTime = resultsDict["activeScanTime"]
 #       self.activeScansSent = resultsDict["activeScansSent"]

        # rmq_socket.detach()
        file_no = rmq_socket.fileno()
        import os
        os.close(file_no)

        self.identified = resultsDict["identified"]
        self.service = service
        self.nmap = resultsDict['nmap']

        printD("SN: BEFORE processService infer method: {}".format(self.identified))
        # pull FULL evidence for device
        mysteryEvidence = dbManager.select(E_DB_FILE, deviceIP)
        # run inference
        printD("SN: processService: {}, {}, {}".format(deviceIP, devicePort, service))
        self.infer(deviceIP, mysteryEvidence, devicePort)
        
#        resultsDict["activeScanTime"] = self.activeScanTime
#        resultsDict["activeScansSent"] = self.activeScansSent
        resultsDict["identified"] = self.identified
        resultsDict['nmap'] = self.nmap
        resultsDict["internal"] = self.resultsDict["internal"]
        resultsDict["external"] = self.resultsDict["external"]

        printD("SN: AFTER processService infer method: {}".format(self.identified))
        return resultsDict

    ##########################################################
    # processNmap()
    ##########################################################
    def processNmap(self, deviceIP, ports, resultsDict, rmq_socket):
        # rmq_socket.detach()
        file_no = rmq_socket.fileno()
        import os
        os.close(file_no)


        if resultsDict['nmap'] == 'yes':
            self.nmap = 'yes'

        # pull FULL evidence for device
        mysteryEvidence = dbManager.select(E_DB_FILE, deviceIP)
        printD("SN: processNmap: deviceIP: {}, ports: {}".format(deviceIP, ports))

        self.infer(deviceIP, mysteryEvidence, ports)

        resultsDict['nmap'] = 'done'
        self.nmap = 'done'

        resultsDict["internal"] = self.resultsDict["internal"]
        resultsDict["external"] = self.resultsDict["external"]
        printD("MP resultsDict: {}".format(resultsDict))

        return resultsDict

    def requestScan(self, mysteryDevice, scan, siteName):
        printD("baseProcessEvidence.requestScan() - ip: {0}, sending request: {1}, {2}, sentScans: {3}".format(mysteryDevice, scan["PARAMS"], siteName, dbManager.select(E_DB_FILE, mysteryDevice).get("ACTIVE_SCANS_SENT", [])))
        self.DBManager.insert(E_DB_FILE, mysteryDevice, {"ACTIVE_SCANS_SENT": [scan["PARAMS"]["SCAN_NAME"]]})
        #self.publish_request("active.requests.{0}".format(siteName), scan["PARAMS"])
        self.resultsDict["external"].append({"ACTIVE_REQUEST_STRING": "active.requests.{0}".format(siteName), "SCAN": scan["PARAMS"]})

