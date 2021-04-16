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

import os
import socket
import fcntl
import struct
import yaml

from flask import Flask, request, Response
from flask_restful import Api, Resource, reqparse
from flask import jsonify
from flask import abort
from flask_cors import CORS
import json
import random
import subprocess
import time
import datetime

scans_path = "ssasse_platform/InferenceEngine/Scans/"

E_DB_FILE = "e_db.sqlite" # evidence
D_DB_FILE = "d_db.sqlite" # devices
V_DB_FILE = "v_db.sqlite" # vendors
VULN_DB_FILE = "vuln_db.sqlite" # vulnerabilities
EVENTS_DB_FILE = "events_db.sqlite" # events
R_DB_FILE = "r_db.sqlite" # requests

from ssasse_platform.InferenceEngine.Databases import dbManager
from ssasse_platform.InferenceEngine import helper
from ssasse_platform.InferenceEngine import similarityScore

ASSETS_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
CORS(app, resources={r"/api/": {"origins": "*"}})
api = Api(app)

##########
#
##########
@app.route("/api/", methods=["GET", "PUT"])
def api_main():
    r = {}
    input = {}
    for key,val in request.form.items():
        input[key] = val
    for key,val in request.args.items():
        input[key] = val

    print("api_main() - input: {0}: ".format(input))

    if request.method == "GET" and ("start" not in input.keys() and "stop" not in input.keys() and "setpolicy" not in input.keys() and "request" not in input.keys()):
        for requestID,requestVal in input.items():
            print("api_main() GET - ID: \"{0}\", Val: \"{1}\"".format(requestID, requestVal))
            try:
                r[requestID] = get(requestID,requestVal)
            except Exception as e:
                print("e: {0}".format(e))
                r[requestID] = "Unavailable"

    elif request.method == "GET" and ("start" in input.keys() or "stop" in input.keys() or "setpolicy" in input.keys() or "request" in input.keys()):
        for requestID,requestVal in input.items():
            print("api_main() PUT - ID: \"{0}\", Val: \"{1}\"".format(requestID, requestVal))
            try:
                r[requestID] = put(requestID,requestVal)
            except:
                r[requestID] = "Unavailable"


    print("return: {0}".format(r))
    return jsonify(r)

##########
#
##########
def get(requestID, requestVal=""):
    r = False

    if requestID == "summary":
        # fill r with home page summary dictionary (aggregate statistic data, table data)
        r = getSummary()

    elif requestID == "details":
        # fill with details dictionary
        #   vulnerabilities, charts, timelines
        r = getDetails(requestVal)

    elif requestID == "policy":
        # fill with policy dictionary
        r = getPolicy()

    elif requestID == "control":
        r = getControl()

    elif requestID == "debug":
        r = getDebug()

    elif requestID == "requests":
        r = getRequests()

    else:
        r = "Get request not found"

    return r

##########
#
##########
def put(requestID, requestVal=""):
    r = False

    if requestID == "start":
        r = start()

    elif requestID == "stop":
        r = stop()

    elif requestID == "setpolicy":
        r = setPolicy(requestVal)

    elif requestID == "request":
        r = putRequest(requestVal)

    else:
        r = "Put request not found"

    return r

##########
#
##########
def start():
    r = subprocess.call("./all_start.sh")

##########
#
##########
def stop():
    r = subprocess.call("./all_stop.sh")

##########
#
##########
def setPolicy(newPolicy):
    newPolicy = json.loads(newPolicy)
    fr = open("ssasse_platform/InferenceEngine/Scans/policy.json", "r", encoding="utf-8")
    oldPolicy = json.loads(fr.read())
    fr.close()

    toDel = []
    for key,val in oldPolicy.items():
        if key not in newPolicy.keys():
            toDel.append(key)
    for key in toDel:
       del oldPolicy[key]

    for key,val in newPolicy.items():
        if key not in oldPolicy.keys():
            oldPolicy[key] = {"scans": []}
        if "scans" not in oldPolicy[key].keys():
            oldPolicy[key]["scans"] = []
        oldPolicy[key]["scans"] = newPolicy[key]["scans"]

    fw = open("ssasse_platform/InferenceEngine/Scans/policy.json", "w", encoding="utf-8")
    fw.write(json.dumps(oldPolicy))
    fw.close()
    r = "done"

##########
#
##########
def putRequest(requestVal):
    print("PUT REQUEST HERE")
    requestDict = json.loads(requestVal)
    print(requestDict)
    requestTimeStamp = requestDict["TIMESTAMP"]
    action = requestDict["ACTION"]

    if action == "pingsweep":
        updated = False
        print("in pingsweep action")
        ipList = []
        fr = open("{0}zonemap.json".format(scans_path), "r", encoding="utf-8")
        zonemap = json.loads(fr.read())
        fr.close()

        print("after file read: {0}".format(zonemap))
        for key,val in requestDict["RESPONSE"].items():

            ipList.append(key)

            if val not in zonemap.keys():
                zonemap[val] = []

            if key not in zonemap[val]:
                zonemap[val].append(key)
                updated = True

        dbManager.DBManager().insert(R_DB_FILE, requestTimeStamp, {"PINGSWEEP": ipList, "RESPONSE": ["sent"]})

        if updated:
            fw = open("{0}zonemap.json".format(scans_path), "w", encoding="utf-8")
            fw.write(json.dumps(zonemap))
            fw.close()

##########
#
##########
def getRequests():
    requestsDict = {}
    allRequestTimeStamps = dbManager.allIdentifiers(R_DB_FILE)
    for requestTimeStamp in allRequestTimeStamps:
        request = dbManager.select(R_DB_FILE, requestTimeStamp)
        if "RESPONSE" not in request:
            requestsDict[requestTimeStamp] = request
    return requestsDict

##########
#
##########
def getSummary():
    summary = {}
    summary["AGGREGATE"] = {}
    summary["AGGREGATE"]["TOTAL_DEVICES"] = 0
    summary["AGGREGATE"]["IDENTIFIED"] = 0
    summary["AGGREGATE"]["UNIDENTIFIED"] = 0
    summary["AGGREGATE"]["TOTAL_VULNERABILITIES"] = 0
    summary["AGGREGATE"]["HIGH_VULNS"] = 0
    summary["AGGREGATE"]["MED_VULNS"] = 0
    summary["AGGREGATE"]["LOW_VULNS"] = 0
    summary["TABLE"] = {}
    summary["REQUESTS"] = getRequests()

    allIPs = dbManager.allIdentifiers(E_DB_FILE)
    for deviceIP in allIPs:
        summary["AGGREGATE"]["TOTAL_DEVICES"] = summary["AGGREGATE"]["TOTAL_DEVICES"] + 1
        summary["TABLE"][deviceIP] = {}
        summary["TABLE"][deviceIP]["VENDOR"] = "NA"
        summary["TABLE"][deviceIP]["MODEL"] = "NA"
        summary["TABLE"][deviceIP]["FIRMWARE_ID"] = "NA"
        summary["TABLE"][deviceIP]["DEVICE_TYPE"] = "NA"
        summary["TABLE"][deviceIP]["HIGH_VULNS"] = 0
        summary["TABLE"][deviceIP]["MED_VULNS"] = 0
        summary["TABLE"][deviceIP]["LOW_VULNS"] = 0

        evidence = dbManager.select(E_DB_FILE, deviceIP)

        # count identified
        if "MODEL" in evidence.keys():
            summary["AGGREGATE"]["IDENTIFIED"] = summary["AGGREGATE"]["IDENTIFIED"] + 1
            summary["TABLE"][deviceIP]["MODEL"] = evidence["MODEL"]
        else:
            summary["AGGREGATE"]["UNIDENTIFIED"] = summary["AGGREGATE"]["UNIDENTIFIED"] + 1

        # fill table
        if "VENDOR" in evidence.keys():
            summary["TABLE"][deviceIP]["VENDOR"] = evidence["VENDOR"]
        if "FIRMWARE_ID" in evidence.keys():
            summary["TABLE"][deviceIP]["FIRMWARE_ID"] = evidence["FIRMWARE_ID"]
        if "DEVICE_TYPE" in evidence.keys():
            summary["TABLE"][deviceIP]["DEVICE_TYPE"] = evidence["DEVICE_TYPE"]

        # find children
        children = getChildren(evidence)
        for key,val in children.items():
            summary["TABLE"][deviceIP+":"+key] = {}
            summary["TABLE"][deviceIP+":"+key]["VENDOR"] = val.get("VENDOR", "NA")
            summary["TABLE"][deviceIP+":"+key]["MODEL"] = val.get("MODEL", "NA")
            summary["TABLE"][deviceIP+":"+key]["FIRMWARE_ID"] = "-"
            summary["TABLE"][deviceIP+":"+key]["DEVICE_TYPE"] = "-"
            summary["TABLE"][deviceIP+":"+key]["HIGH_VULNS"] = "-"
            summary["TABLE"][deviceIP+":"+key]["MED_VULNS"] = "-"
            summary["TABLE"][deviceIP+":"+key]["LOW_VULNS"] = "-"


        # count vulns
        if "VULNERABILITIES" in evidence.keys():
            for vulnerabilityID in evidence["VULNERABILITIES"]:
                summary["AGGREGATE"]["TOTAL_VULNERABILITIES"] = summary["AGGREGATE"]["TOTAL_VULNERABILITIES"] + 1
                vulnerability = dbManager.select(VULN_DB_FILE, vulnerabilityID)
                if helper.singleInList("high", vulnerability["SEVERITY"]):
                    summary["AGGREGATE"]["HIGH_VULNS"] = summary["AGGREGATE"]["HIGH_VULNS"] + 1
                    summary["TABLE"][deviceIP]["HIGH_VULNS"] = summary["TABLE"][deviceIP]["HIGH_VULNS"] + 1
                if helper.singleInList("medium", vulnerability["SEVERITY"]):
                    summary["AGGREGATE"]["MED_VULNS"] = summary["AGGREGATE"]["MED_VULNS"] + 1
                    summary["TABLE"][deviceIP]["MED_VULNS"] = summary["TABLE"][deviceIP]["MED_VULNS"] + 1
                if helper.singleInList("low", vulnerability["SEVERITY"]):
                    summary["AGGREGATE"]["LOW_VULNS"] = summary["AGGREGATE"]["LOW_VULNS"] + 1
                    summary["TABLE"][deviceIP]["LOW_VULNS"] = summary["TABLE"][deviceIP]["LOW_VULNS"] + 1

    return summary



##########
#
##########
def getDetails(deviceIP):
    details = {}
    evidence = dbManager.select(E_DB_FILE, deviceIP)
    details["DEVICE_PROFILE"] = getDeviceProfile(evidence)
    details["VENDOR_PROFILE"] = getVendorProfile(evidence)

    details["CHILDREN"] = getChildren(evidence)
    details["VULNERABILITIES"] = getVulnerabilities(evidence, details["DEVICE_PROFILE"], details["VENDOR_PROFILE"])

    details["TOTAL_VULNERABILITIES"] = 0
    details["HIGH_VULNS"] = 0
    details["MED_VULNS"] = 0
    details["LOW_VULNS"] = 0

    for vulnerabilityID in details["VULNERABILITIES"]:
        details["TOTAL_VULNERABILITIES"] = details["TOTAL_VULNERABILITIES"] + 1
        vulnerability = dbManager.select(VULN_DB_FILE, vulnerabilityID)
        if helper.singleInList("high", vulnerability["SEVERITY"]):
            details["HIGH_VULNS"] = details["HIGH_VULNS"] + 1
        if helper.singleInList("medium", vulnerability["SEVERITY"]):
            details["MED_VULNS"] = details["MED_VULNS"] + 1
        if helper.singleInList("low", vulnerability["SEVERITY"]):
            details["LOW_VULNS"] = details["LOW_VULNS"] + 1

    details["CHARTS"] = getCharts(deviceIP, evidence)
    details["TIMELINES"] = getTimelines(deviceIP)
    return details

##########
#
##########
def getDeviceProfile(evidence):
    deviceProfile = {}
    devices = dbManager.allIdentifiers(D_DB_FILE)
    if "MODEL" in evidence.keys():
        for model in evidence["MODEL"]:
            if model in devices:
                deviceProfile = dbManager.select(D_DB_FILE, model)
                break
    return deviceProfile

##########
#
##########
def getVendorProfile(evidence):
    vendorProfile = {}
    vendors = dbManager.allIdentifiers(V_DB_FILE)
    if "VENDOR" in evidence.keys():
        for vendor in evidence["VENDOR"]:
            if vendor in vendors:
                vendorProfile = dbManager.select(V_DB_FILE, vendor)
                break
    return vendorProfile

##########
#
##########
def getChildren(evidence):
    children = {}
    for key,val in evidence.items():
        if "SERIAL_DEVICES" in key:
            splitKey = key.split("_")
            if len(splitKey) >= 4 and "COM" in splitKey[2].upper():
                if splitKey[2].upper() not in children.keys():
                    children[splitKey[2].upper()] = {}
                children[splitKey[2].upper()][splitKey[-1].upper()] = val[0]
    return children

##########
#
##########
def getVulnerabilities(evidence, deviceProfile, vendorProfile):
    vulnerabilities = {}
    if "VULNERABILITIES" in evidence.keys():
        for vulnID in evidence["VULNERABILITIES"]:
            vuln = dbManager.select(VULN_DB_FILE, vulnID)
            vulnerabilities[vulnID] = vuln
    if "VULNERABILITIES" in deviceProfile.keys():
        for vulnID in deviceProfile["VULNERABILITIES"]:
            vuln = dbManager.select(VULN_DB_FILE, vulnID)
            vulnerabilities[vulnID] = vuln
    if "VULNERABILITIES" in vendorProfile.keys():
        for vulnID in vendorProfile["VULNERABILITIES"]:
            vuln = dbManager.select(VULN_DB_FILE, vulnID)
            vulnerabilities[vulnID] = vuln
    return vulnerabilities

##########
#
##########
def getCharts(deviceIP, evidence):
    charts = {}
    charts["DEVICE"] = {}
    charts["VENDOR"] = {}
    allDevices = dbManager.allIdentifiers(D_DB_FILE)
    allVendors = dbManager.allIdentifiers(V_DB_FILE)

    # TO BE IMPLEMENTED - low priority

    for device in allDevices:
        charts["DEVICE"][device] = {}
        charts["DEVICE"][device]["EVIDENCE"] = dbManager.select(E_DB_FILE, deviceIP)
        charts["DEVICE"][device]["PROFILE"] = dbManager.select(D_DB_FILE, device)
        charts["DEVICE"][device]["SIMILARITY"] = similarityScore.jaccardSimilarity(charts["DEVICE"][device]["EVIDENCE"], charts["DEVICE"][device]["PROFILE"])

    for vendor in allVendors:
        charts["VENDOR"][vendor] = {}
        charts["VENDOR"][vendor]["EVIDENCE"] = dbManager.select(E_DB_FILE, deviceIP)
        charts["VENDOR"][vendor]["PROFILE"] = dbManager.select(V_DB_FILE, vendor)
        charts["VENDOR"][vendor]["SIMILARITY"] = similarityScore.jaccardSimilarity(charts["VENDOR"][vendor]["EVIDENCE"], charts["VENDOR"][vendor]["PROFILE"])

    return charts

##########
#
##########
def getTimelines(deviceIP):
    timelines = {}
    timelines["IDENTIFICATION"] = {}
    timelines["VULNERABILITY"] = {}

    allEvents = dbManager.allIdentifiers(EVENTS_DB_FILE)
    for eventID in allEvents:
        event = dbManager.select(EVENTS_DB_FILE, eventID)
        if "TARGET_IPADDR" in event.keys() and deviceIP in event["TARGET_IPADDR"]:
            if "TYPE" in event.keys() and "IDENTIFICATION" in event["TYPE"]:
                timelines["IDENTIFICATION"][eventID] = event
            if "TYPE" in event.keys() and "VULNERABILITY" in event["TYPE"]:
                timelines["VULNERABILITY"][eventID] = event

    return timelines



##########
#
##########
def getPolicy():
    fr = open("{0}policy.json".format(scans_path), "r", encoding="utf-8")
    policy = json.loads(fr.read())
    fr.close()
    return policy

##########
#
##########
def getControl():
    r = {}
    runningOrNot = subprocess.call("./checkRunning.sh")
    if runningOrNot == 1:
        r["Status"] = "Running"
        fr = open("timeStart")
        startTime = fr.read()
        fr.close()
        seconds = int(float(time.time()) - float(startTime))
        r["Runtime"] = str(datetime.timedelta(seconds=seconds))
    else:
        r["Status"] = "Not running"
        r["Runtime"] = 0.0
    return r

##########
#
##########
def getDebug():
    #r = {}
    #fr = open("dummyDebug.json", "r")
    #r = json.loads(fr.read())
    #fr.close()
    r = json.loads('{    "172.17.0.19":    {        "EVIDENCE": {"PROTOCOLS": ["dnp3", "modbus"], "VENDOR": ["sel"]},        "DECISIONS": {"06302020061217.231": "OUI Lookup", "06302020061237.471": "Config Scan"},        "ERRORS": {},        "SCANS":         {                "scanName1":                {                    "SCAN_RESULT": "",                    "SCAN_RESULT_DESC": ""                },                "scanName2":                {                    "SCAN_RESULT": "",                    "SCAN_RESULT_DESC": ""                }        }    },    "172.17.0.21":    {        "EVIDENCE": {"VENDOR": ["GE"], "MODEL": ["GED20"]},        "DECISIONS": {"06302020061218.231": "OUI Lookup"},        "ERRORS": {},        "SCANS":        {            "scanName1":            {               "SCAN_RESULT": "",                "SCAN_RESULT_DESC": ""           }        }    }}')
    return r

if __name__ == '__main__':
    fr = open("ssasse_platform/config.yml", "r")
    yml = yaml.load(fr, Loader=yaml.FullLoader)
    fr.close()
    ip = yml["ip"]
    apache_cert = yml["apache-certificates"]["public-cert"]
    apache_key = yml["apache-certificates"]["private-key"]
    context = (apache_cert, apache_key)
    #context = ("/home/ubuntu/apacheCerts/apache-selfsigned.crt", "/home/ubuntu/apacheCerts/apache-selfsigned.key")
    app.run(debug=True, host=ip, port=5002, ssl_context=context)
    #app.run(debug=True, host="localhost", port=5002)
    #app.run(debug=True, host=ip, port=5002)
