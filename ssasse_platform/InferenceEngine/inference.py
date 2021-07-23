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

''''
Inference engine running bayseian probability analysis to detect device and it's vulnerabilities
'''

import sys

string_type = None
if sys.version_info[0] >= 3:
    unicode = str
    string_type = str
else:
    string_type = basestring

import logging
logger = logging.getLogger(__name__)
DEBUG = True
def printD(m):
    if DEBUG:
        logger.debug(m)

import os
import json
from os import listdir
from os.path import isfile, join
from math import *
from io import open
import gevent
from gevent import socket as gsock

from gevent import sleep
from gevent.lock import BoundedSemaphore

from time import sleep
import time
import datetime

import multiprocessing
from multiprocessing import Manager
from ipaddress import ip_address, ip_network
import threading

from ..common.actor import Actor
try:
    import yaml
except ImportError:
    raise RuntimeError('PyYAML must be installed before running this script ')

import sqlite3
import json
from .Databases import dbManagerNew
from . import statusTracker

from . import decisionSimple
from . import helper
from . import identifyIP
from . import identifyVulnerabilities

from .identifyIP import IpIdentifier

# Database files
NEW_E_DB_FILE = "new_e_db.sqlite" # new evidence
NEW_EVENTS_DB_FILE = "new_events_db.sqlite" # new events
NEW_D_DB_FILE = "new_d_db.sqlite" # devices
NEW_V_DB_FILE = "new_v_db.sqlite" # vendors
NEW_R_DB_FILE = "new_r_db.sqlite" # requests

# Ignore IP List
IGNORE_IPS = []

# Paths
scans_path = "ssasse_platform/InferenceEngine/Scans/"
vendor_profiles_path = "ssasse_platform/InferenceEngine/Profiles/Vendors"
device_profiles_path = "ssasse_platform/InferenceEngine/Profiles/Devices"

class DeviceIdentificationEngine(Actor):
    def __init__(self, config, rmq_connection):
        printD("InferenceEngine.__init__()")
        super(DeviceIdentificationEngine, self).__init__(config, rmq_connection)

        self.config = config

        thread = threading.Thread(target=self.geventLoop, args=())
        thread.daemon = True

        self.newPortEvidenceQueue = gevent.queue.Queue()
        self.vulnerabilityStatus = {}
        self.identifiedVulnerabilities = {}

        self.identifyIPQueue = multiprocessing.Queue()
        self.identifyVulnQueue = multiprocessing.Queue()

        self.DBManagerNew = dbManagerNew.DBManager()
        self.StatusTracker = statusTracker.StatusTracker()

        self.IpIdentifier = identifyIP.IpIdentifier(self.config, self.DBManagerNew, None)
        self.ServiceProcessor = identifyVulnerabilities.ServiceProcessor(self.config, self.DBManagerNew, None)
        #self.processEvidenceGreenlet = gevent.spawn(self.geventLoop)
        thread.start()
        gevent.spawn(self.setup_subscriptions)

        self.internal_range = self.config.internal_ip_range
        if self.internal_range is None:
            printD("inference -- ERROR: internal range not set. Defaulting to 192.168.0.0/24")
            self.internal_range = "192.168.0.0/24"

        self.ping_sweep_processed = set()

        self.ipRangeScanStatus = dict()
        self.publishActor = None
        self.rmq_socket = self._connection._connection.socket

    def setup_subscriptions(self):
        #printD("InferenceEngine.setup_subscriptions()")
        while not self.connection_ready:
            gevent.sleep(0.01)
        # Subscribe to receive evidence messages from Evidence Manager
        subscriptions = [dict(prefix='new_packet', queue_name='new_packet_queue', callback=self.new_packet_callback),
        dict(prefix='packet', queue_name='evidence_queue', callback=self.evidence_callback),
        dict(prefix='internal', queue_name='internal_queue', callback=self.internal_callback),
        dict(prefix="active.results", queue_name="active_results_queue", callback=self.active_callback)]
        self.add_subscriptions(subscriptions)

    def new_packet_callback(self, topic, message):
        #printD("InferenceEngine.new_packet_callback() - Received: {0}, {1}".format(topic, message))
        pass

    def evidence_callback(self, topic, message):
        #printD("InferenceEngine.evidence_callback() - ip: {0}, evidence callback: {1}, {2}, CTR:{3}".format(message.get("TARGET_IPADDR", None), topic, message, message["CTR"]))
        self.receiveEvidence(message, "Passive")
        #self.receiveQueue.put((message, "Passive"))

    def internal_callback(self, topic, message):
        printD("InferenceEngine.internal_callback() - ip: {0}, internal callback: {1}, {2}".format(message.get("TARGET_IPADDR", None), topic, message))
        self.receiveEvidence(message, "Internal")
        #self.receiveQueue.put((message, "Internal"))

    def active_callback(self, topic, message):
        printD("InferenceEngine.active_callback() - ip: {0}, active callback: {1}, {2}".format(message.get("TARGET_IPADDR", None), topic, message))

        mysteryDevice = message["TARGET_IPADDR"]
        siteName = self.getSiteName(mysteryDevice)

        fromWho = "Active"
        if siteName != "NA":
            fromWho = fromWho + " ({0})".format(siteName)

        if message['SCAN_NAME'] == 'nmap_arp_ping_scan':
            printD("PING Got result for nmap_arp_ping_scan")
            ipRange = message['TARGET_IPADDR']
            self.ipRangeScanStatus[ipRange]["PROCESSING"] = False
            self.ipRangeScanStatus[ipRange]["ACTIVE_SCAN_TIME"] = 0
            
            storedDevices = dbManagerNew.allIPs(NEW_E_DB_FILE)
            # Add IP as separate evidence
            scanResult = message['DISCOVERED_TARGETS']
            for ip, stats in scanResult.items():
                printD("PING: IP:{}, stats: {}".format(ip, stats))
                if ip not in storedDevices:
                    msg = stats
                    msg['TARGET_IPADDR'] = ip
                    printD("PING Adding IP to receiveEvidence: IP: {}, msg: {}".format(ip, msg))
                    self.receiveEvidence(msg, fromWho)
        else:
            self.DBManagerNew.insert(NEW_EVENTS_DB_FILE, mysteryDevice, {"ACTIVE_SCAN_TIME": ["0"]}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Tracking - Active Scan Time")
            self.receiveEvidence(message, fromWho)
        #self.receiveQueue.put((message, fromWho))

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
                    #printD("checking zonemap for ip warning: {0}".format(e))
                    pass
        return "NA"

    ##########################################################
    # vendorMap
    ##########################################################
    def vendorMap(self, vendor):
        #printD("InferenceEngine.vendorMap()")
        v_names = dbManagerNew.allIPs(NEW_V_DB_FILE)
        for realVen in v_names:
            if helper.singleInList(vendor, dbManagerNew.select_all(NEW_V_DB_FILE, realVen)["VENDOR"]):
                vendor = realVen
                break
        return vendor

    ##########################################################
    # modelMap
    ##########################################################
    def modelMap(self, model):
        #printD("InferenceEngine.modelMap()")
        d_names = dbManagerNew.allIPs(NEW_D_DB_FILE)
        for realDev in d_names:
            if helper.singleInList(model, dbManagerNew.select_all(NEW_D_DB_FILE, realDev)["MODEL"]):
                model = realDev
                break
        return model

    #####
    #
    #####
    def spawnIdentifyProcess(self, mysteryDevice):
        resultsDict = {}
        resultsDict["device"] = mysteryDevice
        printD("spawnIdentifyProcess")
        resultsDict = self.IpIdentifier.identifyIP(mysteryDevice, resultsDict, self.rmq_socket)
        if resultsDict is not None:
            self.identifyIPQueue.put(resultsDict)

    #####
    #
    #####
    def identifyProcess(self, mysteryDevice):
        self.DBManagerNew.insert(NEW_EVENTS_DB_FILE, mysteryDevice, {"PROCESSING": "y"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Identification")
        p = multiprocessing.Process(target=self.spawnIdentifyProcess, args=[mysteryDevice])
        p.start()

    #####
    #
    #####
    def getFromIPQueue(self):
        if not self.identifyIPQueue.empty():
            resultsDict = self.identifyIPQueue.get()
            mysteryDevice = resultsDict["device"]
            for internal in resultsDict["internal"]:
                self.receiveEvidence(internal, "Internal")
            for external in resultsDict["external"]:
                printD("publishing ip: {0}, external: {1}".format(mysteryDevice, external))
                #self.publishActor.publish_request(external["ACTIVE_REQUEST_STRING"], external["SCAN"])
                self.publish_messages.append((external["ACTIVE_REQUEST_STRING"], external["SCAN"]))

            self.DBManagerNew.insert(NEW_EVENTS_DB_FILE, mysteryDevice, {"PROCESSING": "n"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Identification")

    ##########################################################
    # startNmapScan: 
    ##########################################################
    def startNmapScan(self, device, ports):
        prevStatus = {}
        prevStatus["device"] = device
        prevStatus["port"] = ports
        prevStatus["nmap"] = 'yes'

        p = multiprocessing.Process(target=self.spawnProcessServiceForNmap, args=(device,ports, prevStatus))
        p.start()
    
    def spawnProcessServiceForNmap(self, device, ports, prevStatus):
        printD("SN: spawnProcessServiceForNmap: {}, {}, {}".format(device, ports, prevStatus))
        currentStatus = self.ServiceProcessor.processNmap(device, ports, prevStatus, self.rmq_socket)
        # Put currentStatus in the multiprocess queue
        self.identifyVulnQueue.put(currentStatus)

    ##########################################################
    # identifyVulnerability: 
    ##########################################################
    def identifyVulnerability(self, device, port, service):
        self.DBManagerNew.insert(NEW_EVENTS_DB_FILE, device, {"PROCESSING": "y"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Vulnerability")
        printD("SN: identifying new vuln: {}, {}, {}".format(device, port, service))

        prevStatus = {}
        identified = 'n'
        for ip_port in self.StatusTracker.IP_PORT:
            ip, pt = ip_port.split('_')
            if ip == device and port == pt:
                identified = 'y'
                break
        prevStatus['device'] = device
        prevStatus['port'] = port
        prevStatus['identified'] = identified
        prevStatus['nmap'] = 'done'
        printD("SN: about to start vuln multiprocess")
        p = multiprocessing.Process(target=self.spawnProcessService, args=(device,port,service,prevStatus))
        p.start()
        printD("SN: just started vuln multiprocess")

    def spawnProcessService(self, device, port, service, prevStatus):
        currentStatus = None
        currentStatus = self.ServiceProcessor.processService(device, port, service, prevStatus, self.rmq_socket)
        # Put currentStatus in the multiprocess queue
        if currentStatus is not None:
            self.identifyVulnQueue.put(currentStatus)

    ##########################################################
    # getFromVulnQueue: Get results from process queue and store it locally
    ##########################################################
    def getFromVulnQueue(self):
        if not self.identifyVulnQueue.empty():
            resultsDict = self.identifyVulnQueue.get()
            printD("SN: getFromVulnQueue() - resultsDict: {}".format(resultsDict))
            mysteryDevice = resultsDict["device"]
            for internal in resultsDict["internal"]:
                self.receiveEvidence(internal, "Internal")
            for external in resultsDict["external"]:
                printD("SN: publishing ip: {0}, external: {1}".format(mysteryDevice, external))
                #self.publishActor.publish_request(external["ACTIVE_REQUEST_STRING"], external["SCAN"])
                self.publish_messages.append((external["ACTIVE_REQUEST_STRING"], external["SCAN"]))

            port = resultsDict["port"]
            identified = 'n'
            identifiedKey = helper.singleInList("identified", resultsDict.keys())
            if identifiedKey:
                identified = resultsDict[identifiedKey]

            if identified.lower() != 'n':
                ip_port = "{}_{}".format(mysteryDevice, port)
                if ip_port not in self.StatusTracker.IP_PORT: self.StatusTracker.IP_PORT.append(ip_port)

            self.DBManagerNew.insert(NEW_EVENTS_DB_FILE, mysteryDevice, {"PROCESSING": "n"}, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), "Vulnerability")
            vulnProtocols = self.getVulnerabilityPorts(mysteryDevice)
            printD("SN: getFromVulnQueue() - IdentifiedVulnerabilities device: {}, ports: {}".format(mysteryDevice, vulnProtocols))
            #printD("Identified Vulnerabilities: {}".format(self.identifiedVulnerabilities))

    ##########################################################
    # geventLoop()
    ##########################################################
    def geventLoop(self):
        printD("InferenceEngine.geventLoop()")
        while not self.connection_ready:
            time.sleep(0.01)
        self.publish_message("inference.start", {})

        peekScanTime = time.time()

        while True:
            time.sleep(0.01)

            # print out debug info
            #printD("inference.geventLoop() - StatusTracker non-empties:")
            #if len(self.StatusTracker.IDENTIFIED) > 0: printD("inference.geventLoop() - StatusTracker.identified: {0}".format(self.StatusTracker.IDENTIFIED))
            #if len(self.StatusTracker.ID_QUEUE) > 0: printD("inference.geventLoop() - StatusTracker.id_queue: {0}".format(self.StatusTracker.ID_QUEUE))
            if len(self.StatusTracker.COMPLETED) > 0: printD("inference.geventLoop() - StatusTracker.completed: {0}".format(self.StatusTracker.COMPLETED))
            if len(self.StatusTracker.VULN_QUEUE) > 0: printD("inference.geventLoop() - StatusTracker.vuln_queue: {0}".format(self.StatusTracker.VULN_QUEUE))
            if len(self.StatusTracker.IP_PORT) > 0: printD("inference.geventLoop() - StatusTracker.ip_port: {0}".format(self.StatusTracker.IP_PORT))
            if len(self.StatusTracker.IP_PORT_SERVICE) > 0: printD("inference.geventLoop() - StatusTracker.ip_port_service: {0}".format(self.StatusTracker.IP_PORT_SERVICE))

            ########## DEVICE IDENTIFICATION ##########
            self.processIdentification()

            ########## SERVICE PROCESSING / VULNERABILITY ##########
            self.processVulnerabilities()
            
            ########## GET FROM MULTIPROCESSING IP QUEUE ##########
            self.getFromIPQueue()

            ########## GET FROM MULTIPROCESSING VULNERABILITY QUEUE ##########
            self.getFromVulnQueue()
            
            userInput = self.checkForPingSweepUserInput()
            if userInput:
                printD("PING: Sending ping sweep: {}".format(userInput))
                self.ping_sweep_handler(userInput)

            currentTime = time.time()
            if currentTime - peekScanTime >= 30:
                printD("PING: Checking for ExternalIPs")
                devices = self.checkForExternalIPs()
                printD("PING: Device list from checkForExternalIPs: {}".format(devices))
                peekScanTime = currentTime
                # Should be from frontend, but for testing purposes
                # ipRangeList = ['172.17.0.0/28']
                # self.ping_sweep_handler(ipRangeList)

                if len(devices) > 0:
                    requestTimeStamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S%f")
                    requestDict = {}
                    requestDict["MESSAGE"] = ["PING: Device list from checkForExternalIPs: {}".format(devices)]
                    self.DBManagerNew.insert(NEW_R_DB_FILE, requestTimeStamp, requestDict, requestTimeStamp, "Requests")

    ##########################################################
    # processIdentification()
    ##########################################################
    def processIdentification(self):
        printD("inference.geventLoop() - ID_QUEUE: {0}".format(self.StatusTracker.ID_QUEUE))
        if not self.newPortEvidenceQueue.empty():
            printD("inference.geventLoop() - VULN_QUEUE: {0}".format(self.newPortEvidenceQueue.peek()))

        ########## IDENTIFICATION ###########
        # Go through evidenceIP queue, find IP that has new evidence waiting
        # remove from list
        mysteryDevice = False
        for mD in self.StatusTracker.ID_QUEUE:
            mysteryEvidence = dbManagerNew.select_all(NEW_E_DB_FILE, mD)
            allEvents = dbManagerNew.select_all(NEW_EVENTS_DB_FILE, mD)
            processingKey = helper.singleInList("PROCESSING", allEvents.keys())
            if self.ipInPolicy(mD) and (not processingKey or "n" in allEvents[processingKey]):
                mysteryDevice = mD
                break

        # If no new evidence, go through IPs currently in an active scan
        #  (so we can see if timeout has passed)
        if mysteryDevice == False:
            devices = dbManagerNew.allIPs(NEW_E_DB_FILE)
            for mD in devices:
                mysteryEvidence = dbManagerNew.select_all(NEW_E_DB_FILE, mD)
                allEvents = dbManagerNew.select_all(NEW_EVENTS_DB_FILE, mD)
                activeScanTimeKey = helper.singleInList("ACTIVE_SCAN_TIME", allEvents.keys())
                if self.ipInPolicy(mD) and activeScanTimeKey and "0" not in allEvents[activeScanTimeKey] and mysteryDevice not in self.StatusTracker.IDENTIFIED:
                    mysteryDevice = mD
                    break

        # run identification process on the chosen IP (mysteryDevice)
        if mysteryDevice != False:
            if mysteryDevice in self.StatusTracker.ID_QUEUE:
                try: self.StatusTracker.ID_QUEUE.remove(mysteryDevice)
                except: pass
            self.identifyProcess(mysteryDevice)

    #####
    #
    #####
    def checkForExternalIPs(self):
        externalDevices = []
        devices = dbManagerNew.allIPs(NEW_E_DB_FILE)
        for device in devices:
            ipAddr = ip_address(device)
            ipNetwk = ip_network(self.internal_range)
            if ipAddr not in ipNetwk and ipAddr not in self.ping_sweep_processed:
                printD("PING: ipAddr: {0} not in ipNetwk: {1}".format(ipAddr, ipNetwk))
                self.ping_sweep_processed.add(ipAddr)
                externalDevices.append(device)
            #else:
                #printD("PING: ipAddr: {0} in ipNetwk: {1}".format(ipAddr, ipNetwk))
        return externalDevices

    # TODO: handle communication between ssass-e and webpage for user input/requests/actions
    def checkForPingSweepUserInput(self):
        allRequestTimeStamps = dbManagerNew.allIPs(NEW_R_DB_FILE)
        for requestTimeStamp in allRequestTimeStamps:
            requestDict = dbManagerNew.select_all(NEW_R_DB_FILE, requestTimeStamp)
            if "DONE" not in requestDict and "PINGSWEEP" in requestDict:
                printD("PING: geventLoop() Ping sweep timestamp: {0}, response: {1}".format(requestTimeStamp, requestDict["PINGSWEEP"]))
                self.DBManagerNew.insert(NEW_R_DB_FILE, requestTimeStamp, {"DONE": ["Y"]}, requestTimeStamp, "Requests")
                return requestDict["PINGSWEEP"]
            #else:
                #printD("PING: User input skipped {0}".format(requestDict))
        return None

    def ping_sweep_handler(self, ipRangeList):
        #targetPorts = '21-23,80,443,502,20000'

        printD("PING: doing sweep on {0}".format(ipRangeList))
        for ipRange in ipRangeList:
            # Check if input format is correct
            runScan = True
            if ipRange in self.ipRangeScanStatus.keys() and "PROCESSING" in self.ipRangeScanStatus[ipRange].keys():
                timeElapsed = self.ipRangeScanStatus["ACTIVE_SCAN_TIME"]
                # Scan is under process and maximum time has not elapsed
                if timeElapsed < 100:
                    runScan = False
            if runScan == True:
                # Get scan parameters
                categoryName = "network_scan"

                scan = self.IpIdentifier.getScanWithoutPolicyCheck("nmap_arp_ping_scan", ipRange, {})
                printD("PING: Scan parameters for nmap_arp_ping_scan: {}".format(scan))
                if scan == "NA":
                    return scan

                scan["PARAMS"]["SCAN_NAME"] = "nmap_arp_ping_scan"
                scan["PARAMS"]["TARGET_IPADDR"] = ipRange
#                scan["TARGET_PORTS"] = targetPorts
                if ipRange not in self.ipRangeScanStatus.keys():
                    self.ipRangeScanStatus[ipRange] = dict()
                self.ipRangeScanStatus["PROCESSING"] = True
                self.ipRangeScanStatus["ACTIVE_SCAN_TIME"] = time.time()

                # siteName from zonemap, which came from user
                siteName = self.getSiteName(ipRange)

                # Kick off new ping sweep scan
                if siteName != "NA":
                    printD("PING: Sending requestScan: ipRange: {}, scan: {} and siteName: {}".format(ipRange, scan, siteName))
                    # self.IpIdentifier.requestScan(ipRange, scan, siteName)
                    # TODO add ping sweep status/history to webpage somehow
                    # self.publish_request("active.requests.{0}".format(siteName), scan["PARAMS"])
                    self.publish_messages.append(("active.requests.{0}".format(siteName), scan["PARAMS"]))
        
    def processVulnerabilities(self):
        ###################################################################
        # If the device has been identified, then newPortEvidenceQueue will 
        # not be empty because it will be ready to process the ports and 
        # services it supports to check for vulnerabilities.
        ###################################################################
        mysteryDevice = False
        port = 0
        service = 0
        IP_PORT_SERVICE = None
        ips = self.StatusTracker.IP_PORT_SERVICE

        printD( "VULN_QUEUE len: {}, entries: {}".format(len(ips), ips))

        for ip_port_service in self.StatusTracker.IP_PORT_SERVICE:
            printD("SN: Retrieving from VULN_QUEUE db {}".format(ip_port_service))

            mD, port, service = ip_port_service.split('|')
            mysteryEvidence = dbManagerNew.select_all(NEW_E_DB_FILE, mD)
            allEvents = dbManagerNew.select_all(NEW_EVENTS_DB_FILE, mD)
            processingKey = helper.singleInList("PROCESSING", allEvents.keys())
            if not processingKey or helper.singleInList("n", allEvents[processingKey]):
                mysteryDevice = mD
                IP_PORT_SERVICE = ip_port_service
                break

        # If no new evidence, go through IPs currently in an active scan
        # (so we can see if timeout has passed)
        if mysteryDevice == False:
            devices = dbManagerNew.allIPs(NEW_E_DB_FILE)
            for mD in devices:

                mysteryEvidence = dbManagerNew.select_all(NEW_E_DB_FILE, mD)
                allEvents = dbManagerNew.select_all(NEW_EVENTS_DB_FILE, mD)
                activeScanTimeKey = helper.singleInList("ACTIVE_SCAN_TIME", allEvents.keys())
                if activeScanTimeKey and "0" not in allEvents[activeScanTimeKey] and "nmap_service_scan" in mysteryEvidence.get("SCAN_NAME", []):

                    #mysteryDevice = mD
                    protocols = self.getProtocols(mD)
                
                    # Check if port done with vulnerabilities check
                    try:
                        vulnProtococols = self.getVulnerabilityPorts(mD)
                        keys_to_delete = []
                        for k, p in protocols.items():
                            if helper.singleInList(p, vulnProtococols):
                                keys_to_delete.append(k)
                        for k in keys_to_delete:
                            del protocols[k] 
                    except KeyError:
                        pass
                    for p, s in protocols.items():
                        port = p
                        service = s
                        break
                    if p != 0 and service != 0:
                        mysteryDevice = mD
                        break

        # run identify vulnerability process on the chosen IP (mysteryDevice), PORT and SERVICE
        if mysteryDevice != False:
            printD("SN: Found ip port to scan: IP: {}, PORT: {}, SERVICE: {}, IP_PORT_SERVICE: {}".format(mysteryDevice, port, service, IP_PORT_SERVICE))
            if IP_PORT_SERVICE is None:
                IP_PORT_SERVICE = "{}|{}|{}".format(mysteryDevice, port, service)
            if IP_PORT_SERVICE in self.StatusTracker.IP_PORT_SERVICE:
                try: self.StatusTracker.IP_PORT_SERVICE.remove(IP_PORT_SERVICE)
                except: pass
            self.identifyVulnerability(mysteryDevice, port, service)


    ##########################################################
    # Get Ports from evidence, vendor profile and device profile
    ##########################################################
    def getProtocols(self, mysteryDevice):
        mysteryEvidence = dbManagerNew.select_all(NEW_E_DB_FILE, mysteryDevice)
        #printD("getPorts: {}".format(mysteryEvidence))
        vendorKey = helper.singleInList("VENDOR", mysteryEvidence.keys())
        #if vendor is None or vendor[0].upper() not in ['SEL', 'GE']:
        #    printD("getPorts for {} returning since vendor is not SEL:{}".format(mysteryDevice, vendor))
        #    return {}
        modelKey = helper.singleInList("MODEL", mysteryEvidence.keys())
        protocols = {}
        # Check for ports info in the evidence
        protocolsKey = helper.singleInList("PROTOCOLS", mysteryEvidence.keys())
        if protocolsKey:
            for scada_protocol in mysteryEvidence[protocolsKey]:
                portKey = helper.singleInList("{0}_PORT".format(scada_protocol), mysteryEvidence.keys())
                if portKey:
                    protocols[scada_protocol] = mysteryEvidence[portKey]
        
        if vendorKey:
            v = self.vendorMap(mysteryEvidence[vendorKey][0]).upper()
            printD("SN: VENDORMAP: INPUT: {}, MAPPED: {}".format(mysteryEvidence[vendorKey][0], v))
            # Read from vendor profile
            vendorPath = "{0}/{1}.json".format(vendor_profiles_path, v)
            protocols = self.getProtocolsFromProfile(vendorPath)

        if modelKey:
            m = self.modelMap(mysteryEvidence[modelKey][0]).upper()
            printD("SN: MODELMAP: INPUT: {}, MAPPED: {}".format(mysteryEvidence[modelKey][0], m))
            # Read from device profile
            if m.upper() == "CONTROLWAVEREMOTEIO":
                m = "ControlWaveRemoteIO"
            modelPath = "{0}/{1}.json".format(device_profiles_path, m)
            modelProtocols = self.getProtocolsFromProfile(modelPath)
            protocols.update(modelProtocols)
        return protocols
    
    ##########
    #
    ##########
    def getProtocolsFromProfile(self, profilePath):
        try:
           fr = open(profilePath, "r", encoding="utf-8")
           profileConfig = json.loads(fr.read())
           fr.close()
        except IOError as e:
           printD("ERROR Cannot open file: {}".format(e))
           return {}

        protocols = {}

        printD("profile Config: {}".format(profileConfig))
        services = profileConfig.get("SERVICES", {})
        scada = profileConfig.get("SCADA", {})
        services.update(scada)

        for service, prts in services.items():
            printD("service: {}, ports: {}".format(service, prts))
            try:
                service_key = service + "_TCP"
                protocols[service_key] = prts["TCP"][0]
            except Exception as e:
                printD("getProtocolsFromProfile() - ERROR: {0}".format(e))
            try:
                service_key = service + "_UDP"
                protocols[service_key] = prts["UDP"][0]
            except Exception as e:
                printD("getProtocolsFromProfile() - ERROR: {0}".format(e))
        printD("getFromProfile: {}".format(protocols))
        return protocols

    #####
    #
    #####
    def processSignature(self, signature, ttl):
        partialEvidence = {}

        relays = []
        rtus = []

        d_devices = dbManagerNew.allIPs(NEW_D_DB_FILE)
        for device in d_devices:
            profile = dbManagerNew.select_all(NEW_D_DB_FILE, device)
            device_type = profile.get("DEVICE_TYPE", None)
            if device_type is not None:
                tcpKey = helper.singleInList("TCP_SIG", profile.keys())
                ttlKey = helper.singleInList("TTL", profile.keys())
                if tcpKey and ttlKey:
                    if helper.singleInList(signature, profile[tcpKey]) and helper.singleInList(ttl, profile[ttlKey]):
                        if device_type[0] == "relay":
                            relays.append(profile)
                        elif device_type[0] == "rtu":
                            rtus.append(profile)

        if len(relays) == 0 and len(rtus) > 0:
            modelKey = helper.singleInList("MODEL", rtus[0].keys())
            vendorKey = helper.singleInList("VENDOR", rtus[0].keys())
            if len(rtus) == 1 and modelKey and False:
                partialEvidence["MODEL"] = rtus[0][modelKey][0]
            if vendorKey:
                partialEvidence["VENDOR"] = rtus[0][vendorKey][0]
            partialEvidence["DEVICE_TYPE"] = "rtu"

        elif len(rtus) == 0 and len(relays) > 0:
            modelKey = helper.singleInList("MODEL", relays[0].keys())
            vendorKey = helper.singleInList("VENDOR", relays[0].keys())
            if len(relays) == 1 and modelKey and False:
                partialEvidence["MODEL"] = relays[0][modelKey][0]
            if vendorKey:
                partialEvidence["VENDOR"] = relays[0][vendorKey][0]
            partialEvidence["DEVICE_TYPE"] = "relay"

        printD("inference.processSignature() - partialEvidence: {0}".format(partialEvidence))

        return partialEvidence

    #####
    #
    #####
    def ipInPolicy(self, mysteryDevice):
        fr = open("{0}policy.json".format(scans_path), "r", encoding="utf-8")
        policy = json.loads(fr.read())
        fr.close()

        if mysteryDevice in policy.keys():
            return True
        else:
            for key in policy.keys():
                if key != "default":
                    try:
                        ipObj = ip_address(mysteryDevice)
                        netObj = ip_network(key)
                        if ipObj in netObj:
                            return True
                            break
                    except Exception as e:
                        #printD("checking policy for ip warning: {0}".format(e))
                        pass
        printD("ipInPolicy() - ip: {0} not in policy".format(mysteryDevice))
        return False

    ##########################################################
    # receiveEvidence(evidence)
    # get all existing evidence for this IP from DB
    # determine which recent evidence is NEW
    # add new evidence to DB (as is, no sanitize)
    # if IP not in queue, add it
    ##########################################################
    def receiveEvidence(self, rawEvidence, fromWho = ""):
        # get mysteryDevice (IP)
        if "TARGET_IPADDR" not in rawEvidence.keys():
            return False
        mysteryDevice = rawEvidence["TARGET_IPADDR"]
        if mysteryDevice in IGNORE_IPS:
            return False

        rawEvidence = helper.breakDownDict(rawEvidence, "", {})

        #if mysteryDevice == "172.17.0.13" and "SCAN_NAME" in rawEvidence.keys() and "http_TCP_header_probe" == rawEvidence["SCAN_NAME"]:
        #    printD("Returning 172.17.0.13 header probe")
        #    return False

        existingEvidence = {}
        newEvidence = {}

        # first occurence of device
        e_devices = dbManagerNew.allIPs(NEW_E_DB_FILE)
        if mysteryDevice not in e_devices:
            printD("receive() - ip: {0}, FIRST".format(mysteryDevice))
            rawEvidence["PROCESSING"] = "n"
            rawEvidence["ACTIVE_SCAN_TIME"] = "0"
        else:
            existingEvidence = dbManagerNew.select_all(NEW_E_DB_FILE, mysteryDevice)

        for rawKey,rawVal in rawEvidence.items():
            rawKey = str(rawKey).strip()

            if isinstance(rawVal, string_type) or isinstance(rawVal, int) or isinstance(rawVal, float):
                rawVal = str(rawVal).strip()
                pass
            else:
                # handle eventually
                continue

            # ignore
            if helper.singleInList(rawKey, ["DEST_PORT", "SOURCE_PORT", "CTR"]) or rawKey.upper().startswith("STATUS") or len(rawVal) < 1 or helper.compareSingle(rawVal, "none"):
                continue

            # conversions
            if rawKey == "PROTOCOL":
                rawKey = "PROTOCOLS"

            # vendor mapping
            if rawKey == "VENDOR":
                oldVal = rawVal
                rawVal = self.vendorMap(rawVal)
                printD("receiveEvidence - ip: {0}, rawVendor: {1}, vendorMap: {2}".format(mysteryDevice, oldVal, rawVal))

            # model mapping
            modelKeys = ["MODEL", "PART_NO", "DEVICE_NAME"]
            if helper.singleInList(rawKey, modelKeys):
                oldVal = rawVal
                #if "MODEL" not in newEvidence.keys():
                #    newEvidence["MODEL"] = []
                rawVal = self.modelMap(rawVal)
                #newEvidence["MODEL"].append(rawVal)
                if rawKey not in existingEvidence.keys():
                    if rawKey not in newEvidence.keys():
                        newEvidence[rawKey] = []
                    newEvidence[rawKey].append(rawVal)
                elif not helper.singleInList(rawVal, existingEvidence[rawKey]):
                    if rawKey not in newEvidence.keys():
                        newEvidence[rawKey] = []
                    if rawVal not in newEvidence[rawKey]:
                        newEvidence[rawKey].append(rawVal)
                printD("receiveEvidence - ip: {0}, rawModel: {1}, modelMap: {2}".format(mysteryDevice, oldVal, rawVal))

            # signature processing
            if rawKey == "TCP_SIG" and "TTL" in rawEvidence.keys():
                partialEvidence = self.processSignature(rawVal, rawEvidence["TTL"])
                for partialKey,partialVal in partialEvidence.items():
                    if partialKey not in existingEvidence.keys():
                        if partialKey not in newEvidence.keys():
                            newEvidence[partialKey] = []
                        newEvidence[partialKey].append(partialVal)
                    elif not helper.singleInList(partialVal, existingEvidence[partialKey]):
                        if partialKey not in newEvidence.keys():
                            newEvidence[partialKey] = []
                        if partialVal not in newEvidence[partialKey]:
                            newEvidence[partialKey].append(partialVal)

            # new key
            if rawKey not in existingEvidence.keys():
                if rawKey not in newEvidence.keys():
                    newEvidence[rawKey] = []
                if rawVal not in newEvidence[rawKey]:
                    newEvidence[rawKey].append(rawVal)
            # existing key, new val
            elif not helper.singleInList(rawVal, existingEvidence[rawKey]):
                if rawKey not in newEvidence.keys():
                    newEvidence[rawKey] = []
                if rawVal not in newEvidence[rawKey]:
                    newEvidence[rawKey].append(rawVal)

        if len(newEvidence.keys()) > 0:
            printD("receive() - ip: {0}, EXISTING: {1}, NEW: {2}".format(mysteryDevice, existingEvidence, newEvidence))

            # add event to events DB - only for passive/active
            if "Passive" in fromWho or "Active" in fromWho:
                eventTimestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S%f")
                event = {}
                event["TYPE"] = ["IDENTIFICATION"]
                event["TARGET_IPADDR"] = [mysteryDevice]

                if "Passive" in fromWho:
                    event["SIGNATURE"] = ["Passive"]
                    if "PROTOCOL" in rawEvidence.keys():
                        event["SIGNATURE"] = [rawEvidence["PROTOCOL"]]
                    elif "PROTOCOLS" in rawEvidence.keys():
                        event["SIGNATURE"] = [rawEvidence["PROTOCOLS"]]
                    elif "SERVICE" in rawEvidence.keys():
                        event["SIGNATURE"] = [rawEvidence["SERVICE"]]
                    event["STATUS"] = ["New Evidence"]

                elif "Active" in fromWho:
                    event["SIGNATURE"] = ["Active"]
                    if "SCAN_NAME" in rawEvidence.keys():
                        event["SIGNATURE"] = [rawEvidence["SCAN_NAME"]]
                        fr = open("{0}scans.json".format(scans_path), "r", encoding="utf-8")
                        scansDict = json.loads(fr.read())
                        fr.close()
                        scanDict = helper.getNested(scansDict, rawEvidence["SCAN_NAME"])
                        if mysteryDevice in self.StatusTracker.IDENTIFIED and scanDict != False and helper.singleInList("vulnerability", scanDict.get("TYPE", [])):
                            event["TYPE"] = ["VULNERABILITY"]
                    event["STATUS"] = ["Results Received"]
                event["INFO"] = [json.dumps(newEvidence)]
                self.DBManagerNew.insert(NEW_EVENTS_DB_FILE, mysteryDevice, event, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), event["TYPE"][0])

            printD("inference inserting new evidence for ip {0}".format(mysteryDevice))

            # insert new evidence into DB (as is, not sanitized)
            evidenceType = "Internal"
            if "Passive" in fromWho:
                evidenceType = "Passive"
            if "Active" in fromWho:
                evidenceType = "Active"
            self.DBManagerNew.insert(NEW_E_DB_FILE, mysteryDevice, newEvidence, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), evidenceType)

            # check if NA vendor needs to be removed
            # if "VENDOR" in newEvidence.keys() and "NA" not in newEvidence["VENDOR"]:
            #     if "VENDOR" in existingEvidence.keys() and "NA" in existingEvidence["VENDOR"]:
            #         self.DBManager.removeVal(E_DB_FILE, mysteryDevice, "VENDOR", "NA")

            # check if identified
            modelKey = helper.singleInList("MODEL", newEvidence.keys())
            if modelKey:
                if mysteryDevice not in self.StatusTracker.IDENTIFIED: self.StatusTracker.IDENTIFIED.append(mysteryDevice)
                if mysteryDevice in self.StatusTracker.ID_QUEUE:
                    try: self.StatusTracker.ID_QUEUE.remove(mysteryDevice)
                    except: pass

                deviceProfile = dbManagerNew.select_all(NEW_D_DB_FILE, newEvidence[modelKey][0])
                if "DEVICE_TYPE" in deviceProfile.keys():
                    newEvidence["DEVICE_TYPE"] = deviceProfile["DEVICE_TYPE"]
                    self.DBManagerNew.insert(NEW_E_DB_FILE, mysteryDevice, newEvidence, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"), ((("Active", "Passive")["Active" in fromWho]), "Internal")["Passive" in fromWho or "Active" in fromWho])

            # add IP to queue to be processed
            printD("receive before() - ID_QUEUE: {0}".format(self.StatusTracker.ID_QUEUE))
            if mysteryDevice not in self.StatusTracker.IDENTIFIED and mysteryDevice not in self.StatusTracker.ID_QUEUE: self.StatusTracker.ID_QUEUE.append(mysteryDevice)
            printD("receive after() - ID_QUEUE: {0}".format(self.StatusTracker.ID_QUEUE))

            scan = {}
            scan["PARAMS"] = {"key": "testing"}
#            self.publish_request("active.requests.pacific", scan["PARAMS"])
            # preps vuln queue
        if True:
            if mysteryDevice in self.StatusTracker.IDENTIFIED:
                printD("SN: New evidence: {}".format(newEvidence))
                printD("SN: Device is identified: {}".format(mysteryDevice))
                if mysteryDevice not in self.ServiceProcessor.processStarted.keys():
                    self.ServiceProcessor.serviceInfo[mysteryDevice] = protocols = self.getProtocols(mysteryDevice)
                    # Kick off nmap scan
                    pts = []
                    for service, port in protocols.items():
                        pts.append(port)
                    printD("SN: starting Nmap Scan for mystery device: {}, ports: {}".format(mysteryDevice, pts))
                    self.startNmapScan(mysteryDevice, pts)
                    self.ServiceProcessor.processStarted[mysteryDevice] = True

                # check if certain scan "nmap_service_scan" came back
                scanName = "nmap_service_scan"
                if helper.singleInList(scanName, dbManagerNew.select_all(NEW_E_DB_FILE, mysteryDevice).get("SCAN_NAME", [])):
                    printD("SN: nmap_service_scan received. mysteryDevice: {}, new evidence: {}".format(mysteryDevice, newEvidence))

                    # Check if port done with vulnerabilities check
                    try:
#                        printD("SN: IdentifiedVulnerabilities ports: {}".format(self.identifiedVulnerabilities))
                        protocols = self.ServiceProcessor.serviceInfo[mysteryDevice]
                        vulnProtocols = self.getVulnerabilityPorts(mysteryDevice)
                        printD("SN: IdentifiedVulnerabilities device: {}, ports: {}, protocols: {}".format(mysteryDevice, vulnProtocols, protocols))
                        keys_to_delete = []
                        for k, p in protocols.items():
                            if helper.singleInList(p, vulnProtocols):
                                printD("SN: Port {} on Device: {} is vulnerability scanned.".format(p, mysteryDevice))
                                keys_to_delete.append(k)
                        for k in keys_to_delete:
                            del protocols[k] 
                    except Exception as e:
                        printD("SN: Error: {0}".format(e))
                    for service, port in protocols.items():
                        ip_port_service = "{}|{}|{}".format(mysteryDevice, port, service)
                        #self.newPortEvidenceQueue.put(mysteryDevice, port, service)
                        printD("SN: db entries: {}, ip_port_service: {}".format(self.StatusTracker.IP_PORT_SERVICE, ip_port_service))
                        if ip_port_service not in self.StatusTracker.IP_PORT_SERVICE: self.StatusTracker.IP_PORT_SERVICE.append(ip_port_service)
                        printD("SN: ip_port_service: {}".format(ip_port_service))
                        #printD("SN: AFTER putting newPortEvidenceQueue: {}".format(self.newPortEvidenceQueue))
        printD("inference.receive() - exiting")

    def getVulnerabilityPorts(self, mysteryDevice):
        vulnProtococols = set()
        ip_ports = self.StatusTracker.IP_PORT
        for ip_port in ip_ports:
            ip, port = ip_port.split('_')
            if ip == mysteryDevice:
                vulnProtococols.add(port)
        
        return vulnProtococols
