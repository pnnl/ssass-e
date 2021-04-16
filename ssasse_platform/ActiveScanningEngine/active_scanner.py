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
Active Scanning Tool collecting evidence for Inference Engine via active scans
'''

import gevent
from gevent.queue import Queue
import json
import os
import sys
#import scanner
from ..common.actor import Actor
from .scanner import Custom_Scanner,Nessus_Scanner,OpenVAS_Scanner,nmap_Scanner
#from ..common.actor import Actor
from ..utils.config_parser import ConfigParser
try:
    import yaml
except ImportError:
    raise RuntimeError('PyYAML must be installed before running this script ')

import logging
_log = logging.getLogger(__name__)



CUSTOM_SCANS = ['dnp3_read_device_attributes', 'dnp3_read_analog_inputs', 'SEL_Relay_get_DeviceInfo', 'SEL_Lantronix_get_DeviceInfo', 'SAGE_Relay_get_DeviceInfo', 'GE_get_IPConfig', 'GE_Relay_get_DeviceInfo', 'GE_get_SCADAConfig', 'dnp3_read_analog_inputs', 'CWETH_get_DeviceInfo', 'get_ssl_cert', 'scrape_http_server', 'scrape_https_server','TELNET_default_cred_Check','FTP_default_cred_Check','RTAC_RTU_get_Device_info','D20_RTU_get_device_info','SEL_HTTP_default_credential_Check','SAGE_HTTP_default_credential_Check','HTTP_unsecured_Check','HTTP_default_credential_Check', 'dnp3_request_link_status','ROC_get_DeviceInfo', 'telnet_grab_banner', 'Lantronix_get_DeviceInfo','RTAC_get_db_device_info']

NESSUS_SCANS = ['snmp_device_info', 'dnp3_TCP_header_probe', 'modbus_TCP_header_probe', 'http_TCP_header_probe']
OPENVAS_SCANS = ['scan2', 'scan3', 'scan4']
NMAP_SCANS = ['nmap_enip_enumerate_scan','nmap_bacnet_discover_enumerate_scan','nmap_s7_enumerate_scan','nmap_codesys_v2_discover_scan','nmap_fox_info_scan','nmap_modicon_info_scan','nmap_omron_tcp_scan','nmap_omron_udp_scan','nmap_pcworx_info_scan','nmap_proconos_info_scan','nmap_custom_scan','nmap_arp_ping_scan','nmap_banner_grab_scan','nmap_service_scan','nmap_TCP_UDP_ping_scan']

active_results_queue = Queue()

class ActiveScanningEngine(Actor):
    def __init__(self, config, rmq_connection):
        super(ActiveScanningEngine, self).__init__(config, rmq_connection)
        print("ActiveScanningEngine Constructor")
        gevent.spawn(self.setup_active_request_subscriptions)
        self._nessus_scan_queue = Queue()
        gevent.spawn(self.do_nessusscan)

        #self._results_greenlets = []
        #self._results_greenlets.append(gevent.spawn(self._scan_results_publisher))

    def setup_active_request_subscriptions(self):
        while not self.connection_ready:
            gevent.sleep()
        # Subscribe to receive active scan request messages from Inference Engine
        prefix = "active.requests.{name}".format(name=self.site_name)
        subscriptions = [dict(prefix=prefix, queue_name='active_request_queue', callback=self.active_request_callback)]
        self.add_subscriptions(subscriptions)

    def active_request_callback(self, topic, message):

        #DO I WANT THIS TO BE IN ITS OWN GEVENT?

        if message['SCAN_NAME'] in NESSUS_SCANS:
            self._nessus_scan_queue.put(message)
        else:
            gevent.spawn(self.do_activescanning(**message))

    def do_nessusscan(self):
        for item in self._nessus_scan_queue:
            self.do_activescanning(**item)
            gevent.sleep(.2)

    def do_activescanning(self, **kwargs):
        #Implement Abstract Scanner Classes else and call them here based on message from Inference Engine
        _log.debug("active scan request: {}".format(kwargs))        
        my_scanner = None
        results = None
        try:

            if kwargs['SCAN_NAME'] in CUSTOM_SCANS:
                my_scanner = Custom_Scanner()
            elif kwargs['SCAN_NAME'] in NESSUS_SCANS:
                my_scanner = Nessus_Scanner()
            elif kwargs['SCAN_NAME'] in OPENVAS_SCANS:
                my_scanner = OpenVAS_Scanner()
            elif kwargs['SCAN_NAME'] in NMAP_SCANS:
                my_scanner = nmap_Scanner()

            active_debug_topic = 'active.debug.{name}'.format(name=self.site_name)

            scan = kwargs.pop('SCAN_NAME')
            _log.debug("Received Active Scan request {} with arguments {}".format(scan, kwargs))
            self.publish_results(active_debug_topic, "Received Active Scan request {} with arguments {}".format(scan, kwargs))

            results = my_scanner.run_scan(scan, **kwargs)
            
            scan = results.get('SCAN_NAME', '')
            active_scan_topic = 'active.results.{name}'.format(name=self.site_name)

            _log.debug("Publishing {} scan results: MSG: {}".format(scan, results))
            self.publish_results(active_debug_topic, "Publishing {} scan results: MSG: {}".format(scan, results))
            self.publish_results(active_scan_topic, results)

        except AttributeError as AE:
            _log.debug(AE)
            raise RuntimeError('Scan name does not exist: {0} - {1}'.format(scan, results))

    #def _active_results_publisher(self):
        #global active_results_queue
        #for item in active_results_queue:
        #    scan = item.get('SCAN_NAME', '')
        #    active_scan_topic = 'active.results'
        #    # Do something with the packet
        #    print("Received {} scan results: MSG:{}".format(scan, item))
        #    #HOW DOES THIS KNOW WHAT QUEUE TO PUT IT ON?
        #    self.publish_results(active_scan_topic, item)
