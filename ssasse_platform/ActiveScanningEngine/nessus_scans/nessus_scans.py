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

try:
    from tenable.sc import TenableSC
    from tenable import errors as tenable_errors
except ImportError:
        print('pyTenable must be installed before running this script ')

import time
from pprint import pprint
import json
import os
from xml.dom import minidom
import zipfile
import re
import logging
_log = logging.getLogger(__name__)

config_path = os.path.join(os.getcwd(), "ssasse_platform", "ActiveScanningEngine", "config.json")
#config_path = "../config.json"
print(config_path)

fr = open(config_path, "r")
CONFIG = json.loads(fr.read())
fr.close()

def dnp3_TCP_header_probe(**kwargs):

    sc = TenableSC(CONFIG['tenable_ip'], port=CONFIG['tenable_port'])
    try:
        sc.login(CONFIG['tenable_username'], CONFIG['tenable_password'])
    except tenable_errors.APIError as APIerror:
        _log.debug("Tenable API error: " + str(APIerror))
        return {'TARGET_IPADDR': kwargs['TARGET_IPADDR'], 'SCAN_NAME': 'dnp3_TCP_header_probe', 'SCAN_RESULT': -1, 'SCAN_RESULT_DESC': json.loads(APIerror.response.text)['error_msg']}

    sc.scans.edit(1, targets=[kwargs['TARGET_IPADDR']])
    running = sc.scans.launch(1)
    scan_results_id = int(running['scanResult']['id'])
    scan_status = sc.scan_instances.details(scan_results_id, fields=['status'])
    while scan_status['status'] != 'Completed':
        time.sleep(15)
        scan_status = sc.scan_instances.details(scan_results_id, fields=['status'])
        if scan_status['status'] == 'Partial' or scan_status['status'] == 'Error':
            scan_error = sc.scan_instances.details(scan_results_id, fields=['errorDetails'])
            return {'TARGET_IPADDR': kwargs['TARGET_IPADDR'], 'SCAN_NAME': 'dnp3_TCP_header_probe', 'SCAN_RESULT': -1, 'SCAN_RESULT_DESC': str(scan_error)}
    
    time.sleep(15) # Give Tenable.sc some time to generate scan results

    filename = str(scan_results_id) + "_" + str(kwargs['TARGET_IPADDR']) + "tcp_scan_data.zip"
    unzipped_filename = str(scan_results_id) + ".nessus"

    with open(filename, 'wb') as fobj:
        sc.scan_instances.export_scan(scan_results_id, fobj)

    if zipfile.is_zipfile(filename):
        with zipfile.ZipFile(filename, 'r') as zipf:
            zipf.extractall("./")

        mydoc = minidom.parse(unzipped_filename)

    else:
        mydoc = minidom.parse(filename)


    report_items = mydoc.getElementsByTagName('ReportItem')
    results = dict.fromkeys(['TARGET_IPADDR', 'SCAN_NAME', 'TTL', 'WINDOW', 'SCALE', 'SACK', 'TIMESTAMP', 'TCP_SIG', 'SCAN_RESULT', 'SCAN_RESULT_DESC'])

    results['TARGET_IPADDR'] = kwargs['TARGET_IPADDR']
    results['SCAN_NAME'] = 'dnp3_TCP_header_probe'

    plugin_found = False    
    for elem in report_items:
        if elem.attributes['pluginID'].value == '999999':
            plugin_found = True
            plugin_output = elem.getElementsByTagName('plugin_output')[0].childNodes[0].data
            sig = plugin_output.split("Signature:")[1].lstrip().rstrip()

    if plugin_found:
        results['SCAN_RESULT'] = 1
        results['SCAN_RESULT_DESC'] = 'Success'
        new_sig = sig.split(':')[1:3] + sig.split(':')[4:]
        results['TCP_SIG'] = ':'
        for part in new_sig:
            results['TCP_SIG'] = results['TCP_SIG'] + part + ':'

        results['TCP_SIG'] = results['TCP_SIG'][:-1]
        results['TTL'] = sig.split(':')[3]
        results['WINDOW'] = sig.split(':')[4]
        if 'W' in sig.split(':')[5]:
            results['SCALE'] = sig.split(':')[6]
        else:
            results['SCALE'] = 'N'
        if 'S' in sig.split(':')[5]:
            results['SCALE'] = 'Y'
        else:
            results['SACK'] = 'N'
        if 'T' in sig.split(':')[5]:
            results['TIMESTAMP'] = 'Y'
        else:
            results['TIMESTAMP'] = 'N'

    os.remove(filename)
    os.remove(unzipped_filename)

    return results

def modbus_TCP_header_probe(**kwargs):

    sc = TenableSC(CONFIG['tenable_ip'], port=CONFIG['tenable_port'])
    try:
        sc.login(CONFIG['tenable_username'], CONFIG['tenable_password'])
    except tenable_errors.APIError as APIerror:
        _log.debug("Tenable API error: " + str(APIerror))
        return {'TARGET_IPADDR': kwargs['TARGET_IPADDR'], 'SCAN_NAME': 'modbus_TCP_header_probe', 'SCAN_RESULT': -1, 'SCAN_RESULT_DESC': json.loads(APIerror.response.text)['error_msg']}

    sc.scans.edit(4, targets=[kwargs['TARGET_IPADDR']])
    running = sc.scans.launch(4)
    scan_results_id = int(running['scanResult']['id'])
    scan_status = sc.scan_instances.details(scan_results_id, fields=['status'])
    while scan_status['status'] != 'Completed':
        time.sleep(15)
        scan_status = sc.scan_instances.details(scan_results_id, fields=['status'])
        if scan_status['status'] == 'Partial' or scan_status['status'] == 'Error':
            scan_error = sc.scan_instances.details(scan_results_id, fields=['errorDetails'])
            return {'TARGET_IPADDR': kwargs['TARGET_IPADDR'], 'SCAN_NAME': 'modbus_TCP_header_probe', 'SCAN_RESULT': -1, 'SCAN_RESULT_DESC': str(scan_error)}
    
    time.sleep(15) # Give Tenable.sc some time to generate scan results

    filename = str(scan_results_id) + "_" + str(kwargs['TARGET_IPADDR']) + "tcp_scan_data.zip"
    unzipped_filename = str(scan_results_id) + ".nessus"

    with open(filename, 'wb') as fobj:
        sc.scan_instances.export_scan(scan_results_id, fobj)


    if zipfile.is_zipfile(filename):
        with zipfile.ZipFile(filename, 'r') as zipf:
            zipf.extractall("./")

        mydoc = minidom.parse(unzipped_filename)

    else:
        mydoc = minidom.parse(filename)

    report_items = mydoc.getElementsByTagName('ReportItem')
    
    results = dict.fromkeys(['TARGET_IPADDR', 'SCAN_NAME', 'TTL', 'WINDOW', 'SCALE', 'SACK', 'TIMESTAMP', 'TCP_SIG', 'SCAN_RESULT', 'SCAN_RESULT_DESC'])
    results['TARGET_IPADDR'] = kwargs['TARGET_IPADDR']
    results['SCAN_NAME'] = 'modbus_TCP_header_probe'

    plugin_found = False
    for elem in report_items:
        if elem.attributes['pluginID'].value == '999999':
            plugin_found = True
            plugin_output = elem.getElementsByTagName('plugin_output')[0].childNodes[0].data
            sig = plugin_output.split("Signature:")[1].lstrip().rstrip()
    
    if plugin_found:
        results['SCAN_RESULT'] = 1
        results['SCAN_RESULT_DESC'] = 'Success'
        new_sig = sig.split(':')[1:3] + sig.split(':')[4:]
        results['TCP_SIG'] = ':'
        for part in new_sig:
            results['TCP_SIG'] = results['TCP_SIG'] + part + ':'

        results['TCP_SIG'] = results['TCP_SIG'][:-1]
        results['TTL'] = sig.split(':')[3]
        results['WINDOW'] = sig.split(':')[4]
        if 'W' in sig.split(':')[5]:
            results['SCALE'] = sig.split(':')[6]
        else:
            results['SCALE'] = 'N'
        if 'S' in sig.split(':')[5]:
            results['SACK'] = 'Y'
        else:
            results['SACK'] = 'N'
        if 'T' in sig.split(':')[5]:
            results['TIMESTAMP'] = 'Y'
        else:
            results['TIMESTAMP'] = 'N'

    os.remove(filename)
    os.remove(unzipped_filename)

    return results

def http_TCP_header_probe(**kwargs):

    sc = TenableSC(CONFIG['tenable_ip'], port=CONFIG['tenable_port'])
    try:
        sc.login(CONFIG['tenable_username'], CONFIG['tenable_password'])
    except tenable_errors.APIError as APIerror:
        _log.debug("Tenable API error: " + str(APIerror))
        return {'TARGET_IPADDR': kwargs['TARGET_IPADDR'], 'SCAN_NAME': 'http_TCP_header_probe', 'SCAN_RESULT': -1, 'SCAN_RESULT_DESC': json.loads(APIerror.response.text)['error_msg']}

    sc.scans.edit(2, targets=[kwargs['TARGET_IPADDR']])
    running = sc.scans.launch(2)
    scan_results_id = int(running['scanResult']['id'])
    scan_status = sc.scan_instances.details(scan_results_id, fields=['status'])
    while scan_status['status'] != 'Completed':
        time.sleep(15)
        scan_status = sc.scan_instances.details(scan_results_id, fields=['status'])
        if scan_status['status'] == 'Partial' or scan_status['status'] == 'Error':
            scan_error = sc.scan_instances.details(scan_results_id, fields=['errorDetails'])
            return {'TARGET_IPADDR': kwargs['TARGET_IPADDR'], 'SCAN_NAME': 'http_TCP_header_probe', 'SCAN_RESULT': -1, 'SCAN_RESULT_DESC': str(scan_error)}

    time.sleep(15) # Give Tenable.sc some time to generate scan results

    filename = str(scan_results_id) + "_" + str(kwargs['TARGET_IPADDR']) + "tcp_scan_data.zip"
    unzipped_filename = str(scan_results_id) + ".nessus"

    with open(filename, 'wb') as fobj:
        sc.scan_instances.export_scan(scan_results_id, fobj)

    if zipfile.is_zipfile(filename):
        with zipfile.ZipFile(filename, 'r') as zipf:
            zipf.extractall("./")

        mydoc = minidom.parse(unzipped_filename)

    else:
        mydoc = minidom.parse(filename)


    report_items = mydoc.getElementsByTagName('ReportItem')
    results = dict.fromkeys(['TARGET_IPADDR', 'SCAN_NAME', 'TTL', 'WINDOW', 'SCALE', 'SACK', 'TIMESTAMP', 'TCP_SIG', 'SCAN_RESULT', 'SCAN_RESULT_DESC'])

    results['TARGET_IPADDR'] = kwargs['TARGET_IPADDR']
    results['SCAN_NAME'] = 'http_TCP_header_probe'

    plugin_found = False    
    for elem in report_items:
        if elem.attributes['pluginID'].value == '999999':
            plugin_found = True
            plugin_output = elem.getElementsByTagName('plugin_output')[0].childNodes[0].data
            sig = plugin_output.split("Signature:")[1].lstrip().rstrip()

    if plugin_found:
        results['SCAN_RESULT'] = 1
        results['SCAN_RESULT_DESC'] = 'Success'
        new_sig = sig.split(':')[1:3] + sig.split(':')[4:]
        results['TCP_SIG'] = ':'
        for part in new_sig:
            results['TCP_SIG'] = results['TCP_SIG'] + part + ':'

        results['TCP_SIG'] = results['TCP_SIG'][:-1]
        results['TTL'] = sig.split(':')[3]
        results['WINDOW'] = sig.split(':')[4]
        if 'W' in sig.split(':')[5]:
            results['SCALE'] = sig.split(':')[6]
        else:
            results['SCALE'] = 'N'
        if 'S' in sig.split(':')[5]:
            results['SCALE'] = 'Y'
        else:
            results['SACK'] = 'N'
        if 'T' in sig.split(':')[5]:
            results['TIMESTAMP'] = 'Y'
        else:
            results['TIMESTAMP'] = 'N'

    os.remove(filename)
    os.remove(unzipped_filename)

    return results

def snmp_device_info(**kwargs):

    sc = TenableSC(CONFIG['tenable_ip'], port=CONFIG['tenable_port'])
    try:
        sc.login(CONFIG['tenable_username'], CONFIG['tenable_password'])
    except tenable_errors.APIError as APIerror:
        _log.error("Tenable API error: " + str(APIerror))
        return {'TARGET_IPADDR': kwargs['TARGET_IPADDR'], 'SCAN_NAME': 'snmp_device_info', 'SCAN_RESULT': -1, 'SCAN_RESULT_DESC': json.loads(APIerror.response.text)['error_msg']}

    sc.scans.edit(3, targets=[kwargs['TARGET_IPADDR']])
    running = sc.scans.launch(3)
    scan_results_id = int(running['scanResult']['id'])
    scan_status = sc.scan_instances.details(scan_results_id, fields=['status'])
    while scan_status['status'] != 'Completed':
        time.sleep(15)
        scan_status = sc.scan_instances.details(scan_results_id, fields=['status'])
        if scan_status['status'] == 'Partial' or scan_status['status'] == 'Error':
            scan_error = sc.scan.instances.details(scan_results_id, fields=['errorDetails'])
            return {'TARGET_IPADDR': kwargs['TARGET_IPADDR'], 'SCAN_NAME': 'snmp_device_info', 'SCAN_RESULT': -1, 'SCAN_RESULT_DESC': str(scan_error)}

    time.sleep(15) # Give Tenable.sc some time to generate scan results
    
    filename = str(scan_results_id) + "_" + str(kwargs['TARGET_IPADDR']) + "tcp_scan_data.zip"
    unzipped_filename = str(scan_results_id) + ".nessus"

    with open(filename, 'wb') as fobj:
        sc.scan_instances.export_scan(scan_results_id, fobj)

    if zipfile.is_zipfile(filename):
        with zipfile.ZipFile(filename, 'r') as zipf:
            zipf.extractall("./")

        mydoc = minidom.parse(unzipped_filename)

    else:
        mydoc = minidom.parse(filename)


    report_items = mydoc.getElementsByTagName('ReportItem')
    results = dict.fromkeys(['TARGET_IPADDR', 'SCAN_NAME', 'VENDOR', 'MODEL', 'SCAN_RESULT', 'SCAN_RESULT_DESC'])

    found_known_device = False
    for elem in report_items:
        if elem.attributes['pluginID'].value == '10800':
            plugin_output = elem.getElementsByTagName('plugin_output')[0].childNodes[0].data
            for line in plugin_output.split('\n'):
                #TODO: Refactor this to use utils.py with a dictionary of values associated with searchable strings
                if '7UT613' in line:
                    found_known_device = True
                    results['MODEL'] = '7UT613'
                    results['VENDOR'] = 'siemens'
                if '7SJ64' in line:
                    found_known_device = True
                    results['MODEL'] = '7SJ64'
                    results['VENDOR'] = 'siemens'

    if found_known_device == True:
        results['SCAN_RESULTS'] = 1
        results['SCAN_RESULTS_DESC'] = 'Success'
    else:
        results['SCAN_RESULTS'] = 0
        results['SCAN_RESULTS_DESC'] = 'Could not determine identity of device at {} from SNMP device info'.format(kwargs['TARGET_IPADDR']) 

    results['TARGET_IPADDR'] = kwargs['TARGET_IPADDR']
    results['SCAN_NAME'] = 'snmp_device_info'

    os.remove(filename)
    os.remove(unzipped_filename)

    return results


