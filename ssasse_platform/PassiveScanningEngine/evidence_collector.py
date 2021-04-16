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
Packet collector on sensor box and send to Site Coordinator.
'''

import gevent
import os
import sys
import logging
import datetime
import subprocess
import glob
import subprocess
from os import path
from gevent.queue import Queue
from ..common.actor import Actor
from ..utils.config_parser import ConfigParser
from .operation import Operation
from .parse_packet import parse_packet, parse_tcp_packet, parse_service_packet
from .parse_data_value import parse_data_value

_log = logging.getLogger(__name__)

BRO_AVAILABLE = True
try:
    import broker
except ImportError:
    _log.debug("Broker module is unavailable. Please build python binding of broker module")
    BRO_AVAILABLE = False

NNM_AVAILABLE = False

if not path.exists("/opt/nnm/var/nnm/logs"):
    NNM_AVAILABLE = False

known_plugin_ids = {
'dnp3':[7226, 7089, 7090, 7097, 7094, 7095, 7096, 7097, 7510, 7512, 7511, 7513, 7514, 7515, 7516, 7517],
'modbus':[90, 7091, 7092, 7100, 7101, 7102, 7103, 7104, 7105],
'bacnet':[6726, 7165, 7110, 6728],
'cip':[8277, 8278, 8291, 7228, 7113, 7114, 7115, 7144],
'dhcp':[7186],
'udp':[110],
'icmp':[111]
}

dnp3_plugin_ids = [7226, 7089, 7090, 7097, 7094, 7095, 7096, 7097, 7512, 7511, 7513, 7514, 7515, 7516]
modbus_plugin_ids = [90, 7091, 7092, 7100, 7101, 7102, 7103, 7104, 7105]
bacnet_plugin_ids = [6726, 7165, 7110, 6728]
cip_plugin_ids = [8277, 8278, 8291, 7228, 7113, 7114, 7115, 7144]
dhcp_plugin_ids = [7186]
udp_plugin_ids = [110]
icmp_plugin_ids = [111]

dnp3_functioncode_mapping = {
7511: {'fc': '13', 'fn': 'COLD_RESTART'},
7512: {'fc': '14', 'fn': 'WARM_RESTART'},
7513: {'fc': '18', 'fn': 'STOP_APPL'},
7514: {'fc': '21', 'fn': 'DISABLE_UNSOLICITED'},
7515: {'fc': '01', 'fn': 'READ'},
7516: {'fc': '129', 'fn': 'RESPONSE'}
}

modbus_functioncode_mapping = {
7099: {'fc': '08_00', 'fn': 'DIAGNOSTICS_RETURN_QUERY_DATA'},
7100: {'fc': '08_01', 'fn': 'RESTART_COMMUNICATIONS'},
7101: {'fc': '08_04', 'fn': 'FORCE_LISTEN_MODE'},
7102: {'fc': '08_10', 'fn': 'CLEAR_COUNTERS_AND_DIAGNOSTIC_REGISTER'},
7103: {'fc': '11',    'fn': 'REPORT_SERVER_ID'},
7104: {'fc': '43_13', 'fn': 'ENCAP_INTERFACE_TRANSPORT_CAN_OPEN'},
7105: {'fc': '43_14', 'fn': 'ENCAP_INTERFACE_TRANSPORT_DEVICE_IDENTIFICATION'}
}

protocol_packet_queue = Queue()
modbus_packet_queue = Queue()
cip_packet_queue = Queue()
bacnet_packet_queue = Queue()
new_packet_queue = Queue()
service_packet_queue = Queue()

_log = logging.getLogger(__name__)


class EvidenceCollector(Actor):
    def __init__(self, config, rmq_connection):
        super(EvidenceCollector, self).__init__(config, rmq_connection)
        config_path = os.path.join(os.getcwd(), 'ssasse_platform', 'PassiveScanningEngine', 'sensor_box_config.yml')
        sensor_config_obj = ConfigParser(config_path)

        _log.debug("Site Evidence Collector Constructor")
        _log.debug("Config params: {}".format(sensor_config_obj.config_opts))
        self.name = self.site_name
        self._protocols = sensor_config_obj.config_opts.get('protocols', [])
        self._bro_ip = sensor_config_obj.config_opts.get('bro-ip', '127.0.0.1')
        self._bro_port = sensor_config_obj.config_opts.get('bro-port', 9999)
        self._bro_service = sensor_config_obj.config_opts.get('bro-service', False)
        self._bro_install_path = sensor_config_obj.config_opts.get('bro-install-path', None)
        self._proto_greenlets = []
        if BRO_AVAILABLE:
            self.check_bro_running()
        self._proto_greenlets.append(gevent.spawn(self._protocol_packet_publisher))
        #self._proto_greenlets.append(gevent.spawn(self._service_packet_publisher))
        self._proto_greenlets.append(gevent.spawn(self._new_packet_publisher))
        self._proto_greenlets.append(gevent.spawn(self.setup_command_subscriptions))
        self.counter = 0
        self.ctr = 0
        self._inference_running = False

    def check_bro_running(self):
        _log.debug("ZEEK AVAILABLE")
        _log.debug("Checking if ZEEK service is running")
        if self._bro_service and self._bro_install_path is not None:
            status_cmd = ['sudo', os.path.join(self._bro_install_path, 'bin/zeekctl'), 'status']
            _log.debug("cmd:{}".format(status_cmd))
            res = subprocess.run(status_cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            if res.returncode != 0:
                start_cmd = ['sudo', os.path.join(self._bro_install_path, 'bin/zeekctl'), 'start']
                _log.error("Zeek is not running. Starting ZEEK ")
                res = subprocess.run(start_cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
                if res.returncode != 0:
                    _log.error("Zeek startup failed. Exitting!")
                    sys.exit()

    def setup_command_subscriptions(self):
        while not self.connection_ready:
            gevent.sleep(0.5)
        _log.debug("Connection ready: {}".format(self.name))
        subscriptions = [dict(prefix='inference', queue_name='command_queue', callback=self.command_callback)]
        self.add_subscriptions(subscriptions)
        if BRO_AVAILABLE:
            _log.debug("ZEEK AVAILABLE")
            self._proto_greenlets.append(gevent.spawn(self.bro_listener))
        if NNM_AVAILABLE:
            _log.debug("NNM AVAILABLE")
            self._proto_greenlets.append(gevent.spawn(self.nnm_log_parser))

    def bro_listener(self):
        ep = broker.Endpoint()
        sub = ep.make_subscriber("bro_analyser")
        ep.listen("127.0.0.1", 9999)
        _log.debug("ZEEK listener loop")

        while not self.connection_ready:
            _log.debug("connection not ready")
            gevent.sleep(0.5)

        while True:
            try:
                if not sub.available():
                    #_log.debug("waiting for bro event")
                    gevent.sleep(0.02)
                else: 
                    gevent.sleep(0.01)
                    (topic, msg) = sub.get()
                    ev = broker.zeek.Event(msg)
#                    _log.debug("ev DATA: {}".format(ev.args()))
                    # Process the bro event not when inference is running
                    if self._inference_running:
    #                   if topic == "bro_analyser/data_get":
    #                       pkt = parse_data_value(ev.args())
    #                       _log.debug("DNP3 DATA: {}".format(pkt))
                        if topic == "bro_analyser/tcp_packet_get":
                            pkt = parse_tcp_packet(ev.args())
                            item = pkt.getDict()
                            #_log.debug("NEW TCP packet received from bro: {}".format(item))
                            new_packet_queue.put_nowait(item)
                        if topic in ["bro_analyser/dnp3_packet",
                                    "bro_analyser/modbus_packet",
                                    "bro_analyser/bacnet_packet",
                                    "bro_analyser/cip_packet"]:
                            pkt = self.parse_operation(ev.args())
                            item = pkt.getDict()
                            #_log.debug("Protocol operation packet: {}".format(item))
                            
                            global protocol_packet_queue
                            protocol_packet_queue.put_nowait(item)
                        if topic in ["bro_analyser/http_packet",
                                    "bro_analyser/ssh_packet",
                                    "bro_analyser/telnet_packet"]:
                            #_log.debug("ev DATA: {}".format(ev.args()))
                            pkt = parse_service_packet(ev.args())
                            p = ev.args()[0]
                            #for i in range(1, len(p)):
                            #    _log.debug("RAW Service packet: {}, {}".format(i, p[i]))
                            item = pkt.getDict()
                            #_log.debug("Service packet: {}, {}".format(pkt.service, item))
                            #global service_packet_queue
                            protocol_packet_queue.put_nowait(item)
                        if topic == "bro_analyser/rocplus_packet":
                            #_log.debug("ROCPlus packet: {}".format(ev.args()));
                            opn = self.parse_rocplus_operation(ev.args())
                            if opn is not None:
                                #_log.debug("ROCPLUS opn: {}".format(opn))
                                roc_item = opn.getDict()
                                protocol_packet_queue.put_nowait(roc_item)

                    if topic == "bro_analyser/bro_done":
                        ep.shutdown()
                        _log.debug("Listener quit!")
            except KeyboardInterrupt as e:
                _log.debug("Keyboard interrupt received. shutting down bro listener loop")
                ep.shutdown()
            except TypeError as e:
                _log.debug("TypeError: {}".format(e))
                ep.shutdown()
                
    def _new_packet_publisher(self):
        new_packet_topic = 'tcp_packet.{sensor_box}'.format(sensor_box=self.name)
        _log.debug("new_packet")
        for item in new_packet_queue:
            # Publish TCP packet to inference engine
            #_log.debug("Received NEW TCP packet: {}".format(item))
            self.publish_evidence(new_packet_topic, item)

    def _service_packet_publisher(self):
        service_packet_topic = 'service_packet.{sensor_box}'.format(sensor_box=self.name)
        _log.debug("service_packet")
        for item in service_packet_queue:
            # Publish SERVICE packet to inference engine
            _log.debug("Received NEW SERVICE packet: {}".format(item))
            self.publish_evidence(service_packet_topic, item)

    def _protocol_packet_publisher(self):
        global protocol_packet_queue
        _log.debug("protocol_packet_queue")
        try:
            for item in protocol_packet_queue:
                #proto = item.get('protocol', '')
                protocol_packet_topic = 'packet.{sensor_box}'.format(sensor_box=self.name)
                # Do something with the packet
                self.publish_evidence(protocol_packet_topic, item)
                #_log.debug("Received {} packet: MSG:{}".format(protocol_packet_topic, item))
        except KeyboardInterrupt:
            _log.debug("Keyboard interrupt received. Shutting down packet publisher loop")

    def command_callback(self, topic, message):
        # Callback method to act on the command
        _log.debug("Command message received: From: {}, Message: {}".format(topic, message))
        if topic == 'inference.start':
            self._inference_running = True
        elif topic == 'inference.stop':
            self._inference_running = False
        else:
            pass

    def parse_operation(self, args):
        protocol_info = args[0]
        operation = Operation()
        # Timestamp
        #operation.ts = (protocol_info[0] - datetime.datetime(1970, 1, 1)).total_seconds()
       
        # Is from the originator side of the connection
        operation.is_orig = protocol_info[6]
#        _log.debug("source and destination ips: {}".format(protocol_info[1]))
#        _log.debug("source and destination macs: {}, {}".format(protocol_info[1][1], protocol_info[1][2]))
       
        if operation.is_orig == 1:
            # Connection IPs and ports
            operation.source_ip = str(protocol_info[1][0][0])
            operation.source_port = str(protocol_info[1][0][1])
            operation.source_macaddress = str(protocol_info[1][1][5])

            operation.destination_ip = str(protocol_info[1][0][2])
            #_log.debug("Operation packet: {}, {}".format(operation.destination_ip, str(protocol_info[1][0][2])))
            operation.destination_port = str(protocol_info[1][0][3])
            operation.dest_macaddress = str(protocol_info[1][2][5])
        else:
            # Flip Connection IPs and ports 
            # (since is_orig=0, data is coming from other direction)
            operation.destination_ip = str(protocol_info[1][0][0])
            operation.destination_port = str(protocol_info[1][0][1])
            operation.source_macaddress = str(protocol_info[1][2][5])

            #_log.debug("Operation packet: {}, {}".format(operation.destination_ip, str(protocol_info[1][0][0])))
            operation.source_ip = str(protocol_info[1][0][2])
            operation.source_port = str(protocol_info[1][0][3])
            operation.dest_macaddress = str(protocol_info[1][1][5])

        pos = operation.source_port.find('/')
        if pos != -1:
            operation.source_port = operation.source_port[:pos]
        pos = operation.destination_port.find('/')
        if pos != -1:
            operation.destination_port = operation.destination_port[:pos]
        # Control Protocol (service)
        operation.protocol = str(protocol_info[2])
        uid = str(protocol_info[3])
        if operation.protocol.lower() == 'dnp3':
            # uid
            if operation.is_orig:
                master, slave = uid.split(':')
            else:
                slave, master = uid.split(':')
            #master, slave = uid.split(':')
            operation.dnp3_master_id = master
            operation.dnp3_slave_id = slave
            operation.is_master_slave = True
            operation.dnp3_port = ''
            if operation.is_orig != 1:
                operation.dnp3_port = operation.source_port
        elif operation.protocol.lower() == 'modbus':
            # uid
            operation.modbus_slave_id = uid
            operation.is_master_slave = True
            if operation.is_orig != 1:
                operation.modbus_port = operation.source_port

        # Function code
        operation.fc = protocol_info[4].value

        # Function name
        operation.fn = str(protocol_info[5])
        operation.ctr = self.ctr
        self.ctr = self.ctr + 1
        return operation

    def nnm_log_parser(self):
        filelist = glob.glob('/opt/nnm/var/nnm/logs/realtime-logs*.txt')
        files = sorted(filelist, key=os.path.getctime, reverse=True)
        fn = files[0]

        #fn = "/opt/nnm/var/nnm/logs/realtime-logs-2.txt"
        p = subprocess.Popen(["sudo", "tail", "-f", fn], stdout=subprocess.PIPE)
        keep_running = True
        while keep_running == True:
            try:
                line = p.stdout.readline()
                if not line:
                    _log.debug("Empty")
                    gevent.sleep(2)
                else:
                    item = self.parse_line(line)
                    item = item.getDict()
                    protocol_packet_queue.put_nowait(item)
                #_log.debug("Parsing line: {}".format(line))
                gevent.sleep(0.1)
            except KeyboardInterrupt:
                _log.debug("exiting...")
                keep_running = False

    def parse_line(self, line):
        parts = line.split('|')
       
        operation = Operation()
        _log.debug("Line: {}, parts: {}".format(line, parts))
        if isinstance(parts, list):
            first_frame = parts[0].split('nnm')
            ts = first_frame[0][:-1]
            addr = first_frame[1][1:]
            ip, port = addr.split(':')
            _log.debug("source ip: {}, port: {}".format(ip, port))
            operation.source_ip = ''.join(ip.split())
            operation.source_port = ''.join(port.split())
            dest_ip, dest_port = parts[1].split(':')
            _log.debug(dest_ip, dest_port)      
            operation.destination_ip = dest_ip
            operation.destination_port = dest_port
            #operation.service = parts[4]
            id = int(parts[3])
            _log.debug("Plugin ID: {}".format(id))
            operation.protocol = self.get_protocol(id)

            fc_mapping = self.get_dnp3_function_code(id)
            if fc_mapping is not None and isinstance(fc_mapping, dict):
                operation.fc = fc_mapping['fc']
                operation.fn = fc_mapping['fn']
            elif id == 7186: # DHCP Client Detection
                dns_info = parts[6].split('Host Name: ')
                mac = dns_info[1].split(' Host MAC: ')
                operation.hostname = mac[0]
                operation.source_macaddress = mac[1]
            if operation.protocol == 'dnp3':
                plugin_output = parts[6]
                if plugin_output != "N/A":
                    info = parts[6].split('Source ID:')
                    src_dest = info[1].split(' Destination ID:')
                    operation.dnp3_master_id = src_dest[0]
                    operation.dnp3_slave_id = src_dest[1]
                    operation.is_master_slave = True
                    if operation.source_port != 0:
                        operation.dnp3_port = operation.source_port

        _log.debug("Final operation: {}".format(operation))
        return operation

    def get_dnp3_function_code(self, plugin_id):
        fc = None
        if plugin_id >= 7511 or plugin_id <= 7516:
           try:
               fc = dnp3_functioncode_mapping[plugin_id]
           except KeyError as e:
               pass
        elif plugin_id >= 7099 or plugin_id <= 7105:
            try:
               fc = modbus_functioncode_mapping[plugin_id]
            except KeyError:
               pass
        else:
           pass
        return fc

    def get_protocol(self, plugin_id):
        protocol = ''
        for proto, ids in known_plugin_ids.iteritems():
            if plugin_id in ids:
                protocol = proto
                break
        return protocol


