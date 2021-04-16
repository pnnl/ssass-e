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

import binascii
import os
import socket
import sys
import crcmod
import time
import itertools
import struct
import json
import subprocess
import shlex
import pyshark
import re
import xml.etree.ElementTree as ET
from xml.dom import minidom
import logging
_log = logging.getLogger(__name__)

from multiprocessing import Process, Queue

CRC_Fun = crcmod.predefined.mkPredefinedCrcFun("crc-16-dnp")
pkt_count = 1

config_path = os.path.join(os.getcwd(), "ssasse_platform", "ActiveScanningEngine", "config.json")
#config_path = "../config.json"
print(config_path)

fr = open(config_path, "r")
CONFIG = json.loads(fr.read())
fr.close()

def my_function(q, cap_filter):
    global pkt_count
    capture = pyshark.LiveCapture(CONFIG['scanning_interface'], display_filter=cap_filter, use_xml=True)
    try:
        capture.apply_on_packets(parse_packet, packet_count=2)
        q.put(pkt_count)
    except Exception as exc:
        _log.error(exc)

def parse_packet(packet):

    global pkt_count
    doc = minidom.parseString(str(packet, 'utf-8'))
    f = open("packet" + str(pkt_count) + ".xml", "w")
    doc.writexml(f)
    f.close()
    pkt_count += 1

def check_crc(buff, count):
    count -= 2
    tmp_buff = buff[:-2]
    crc = CRC_Fun(bytes(tmp_buff))
    count += 2
    if hex(buff[count-2]) != hex(crc & 0xff) or hex(buff[count-1]) != hex(crc >> 8):
        return 1
    else:
        return 0

def isNthBitSet(integer, n):
    if integer & (1 << (n - 1)):
        return True
    else:
        return False

def mygrouper(n, iterable):
    args = [iter(iterable)] * n
    return ([e for e in t if e != None] for t in itertools.izip_longest(*args))


def dnp3_request_link_status(master, slave, ip, port):

    DNP_COMS = False
    SOCK_ERR_FLAG = False
    dnp3_data_link_header = [0x05, 0x64, 0x05, 0xc9]
    ip_address = ip
    dnp3_slave = slave
    dnp3_master = master

    dnp3_data_link_header.append(dnp3_slave & 0xff)
    dnp3_data_link_header.append(dnp3_slave >> 8)
    dnp3_data_link_header.append(dnp3_master & 0xff)
    dnp3_data_link_header.append(dnp3_master >> 8)

    req_info = bytearray(struct.pack('B B B B B B B B', *dnp3_data_link_header))
    dnp3_data_link_checksum = CRC_Fun(bytes(req_info))
    req_info.append(dnp3_data_link_checksum & 0xff)
    req_info.append(dnp3_data_link_checksum >> 8)

    dnp_port = port

#Open connection
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (ip_address, dnp_port)
    sock.settimeout(10)
#Send packet and receive response

    #print("GOT HERE")

    try:
        #print('sending {!r}'.format(binascii.hexlify(req_info)))
        sock.connect(server_address)
        #print "GOT HERE1"
        sock.sendall(req_info)
        res = sock.recv(1024)

        is_Status = 0
        crc_check = 0
        tmp_dnp_data = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        tmp_dnp_data_counter = 0

        if (res):
            length_offset = 2
            DL_control_offset = 3

            for i in range(len(res)):
                if res[i] == 0x05 and res[i+1] == 0x64:
                    if res[i+DL_control_offset] == 0x0b:
                        is_Status = 1
                        for j in range(i+int(res[i+length_offset]) + 5):
                            tmp_dnp_data[tmp_dnp_data_counter] = res[j]
                            tmp_dnp_data_counter += 1
                        tmp_dnp_data = bytearray(tmp_dnp_data)
                    else:
                        is_Status = 0

            if is_Status == 1:
                crc_check = check_crc(tmp_dnp_data, tmp_dnp_data_counter)
                if crc_check == 0:
                    DNP_COMS = True

    except socket.error as error:
        _log.error("Not able to establish connection on port {} with {}: Socket Error: {}".format(port, ip, error))
        if str(error) != "[Errno 104] Connection reset by peer":
            SOCK_ERR_FLAG = True
    finally:
   #     print('closing socket')
        sock.close()
        return (DNP_COMS, SOCK_ERR_FLAG)

def dnp3_read_analog_inputs(ip_address, dnp3_port, dnp3_master, dnp3_slave):
    
    global pkt_count

    #print("dnp3_read_device_attributes: {}".format(kwargs))

    #print "Got to dnp3_read_device_attributes"
    dnp3_data_link_header = [0x05, 0x64, 0x0b, 0xc4]

    dnp3_data_link_header.append(dnp3_slave & 0xff)
    dnp3_data_link_header.append(dnp3_slave >> 8)
    dnp3_data_link_header.append(dnp3_master & 0xff)
    dnp3_data_link_header.append(dnp3_master >> 8)

    dnp3_data = [0xc0, 0xc0, 0x01, 0x1e, 0x00, 0x06]

    #---------------MAIN--------------------

    #Calculate Checksums

    packed_dnp3_data_link_header = bytearray(struct.pack('B B B B B B B B', *dnp3_data_link_header))
    dnp3_data_link_checksum = CRC_Fun(bytes(packed_dnp3_data_link_header))
    packed_dnp3_data_link_header.append(dnp3_data_link_checksum & 0xff)
    packed_dnp3_data_link_header.append(dnp3_data_link_checksum >> 8)

    packed_dnp3_application_data = bytearray(struct.pack('B B B B B B', *dnp3_data))
    dnp3_data_checksum = CRC_Fun(bytes(packed_dnp3_application_data))
    packed_dnp3_application_data.append(dnp3_data_checksum & 0xff)
    packed_dnp3_application_data.append(dnp3_data_checksum >> 8)


    #Build Packet Data
    req_info =  packed_dnp3_data_link_header + packed_dnp3_application_data

    #print("Before Request Link Status")

    retry_count = 2

    while retry_count > 0:

        time.sleep(10)
        DNP3_COMS, SOCK_ERR_FLAG = dnp3_request_link_status(dnp3_master, dnp3_slave, ip_address, dnp3_port)
        if DNP3_COMS == True or SOCK_ERR_FLAG == True:
            break
        retry_count -= 1

    results = dict.fromkeys(['TARGET_IPADDR', 'SCAN_NAME', 'DNP3_COMMS', 'MULTIPLE_ANINP_OBJ', 'DEFAULT_ANINP_VAR', 'SCAN_RESULT', 'SCAN_RESULT_DESC'])
    results['TARGET_IPADDR'] = ip_address
    results['SCAN_NAME'] = 'dnp3_read_analog_inputs'
 
    #print("After Request Link Status")
    #Sleep to provide time for connection to close properly
    if SOCK_ERR_FLAG == True:
        results['SCAN_RESULT'] = -1
        results['SCAN_RESULT_DESC'] = 'Socket error connecting to {0}:{1}'.format(ip_address, dnp3_port)
        return results

    if DNP3_COMS:
        #print('dnp3_coms == true')
        time.sleep(3)

    #Open connection
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (ip_address, dnp3_port)
    sock.settimeout(10)

    #Send packet and receive response

    #print "before results"

    objvar_list = []
    objvar_counter = 0

    #Check if DNP3 Communication is even possible

    if not DNP3_COMS:
        results['DNP3_COMMS'] = 0
        results['SCAN_RESULT'] = 0
        results['SCAN_RESULT_DESC'] = 'No Link Status returned from DNP3 slave at {0}. It is possible that the slave device does not accept the scanner as a master'.format(ip_address)
        return results
    else:
        results['DNP3_COMMS'] = 1

        try:
            cap_filter = "dnp3 and ip.addr == " + str(ip_address)
            queue = Queue()
            p = Process(target=my_function, args=(queue, cap_filter))
            p.start()
            #Give tshark a second to start
            time.sleep(3)
            sock.connect(server_address)
            sock.sendall(req_info)
            res = sock.recv(1024)
            p.join() #this blocks until the process terminate
            pkt_count = queue.get()
            for i in range(1, pkt_count):
                tree = ET.parse('packet' + str(i) + '.xml')
                root = tree.getroot()
                #ET.dump(root)
                for child in root:
                    if child.get('name') == 'dnp3':
                        for child2 in child:
                            if 'Application Layer: ' in child2.get('show'):
                                for child3 in child2:
                                    if child3.get('show') == 'RESPONSE Data Objects':
                                        for child4 in child3:
                                            if child4.get('name') == 'dnp3.al.obj':
                                                pattern = re.compile("\(Obj:[0-9]+, Var:[0-9]+\)")
                                                objvar = pattern.findall(child4.get('showname'))[0]
                                                if objvar != None:
                                                    objvar_counter += 1
                                                    results['DEFAULT_ANINP_VAR'] = objvar.split(':')[2][0:-1]
                                                    
                os.remove('packet' + str(i) + '.xml')

            if objvar_counter > 1:
                results['MULTIPLE_ANINP_OBJ'] = 1
                results['DEFAULT_ANINP_VAR'] = None

        except socket.error as error:
            _log.error("Not able to establish connection on port {} with {}: Socket Error: {}".format(dnp3_port, ip_address, error))
            SOCK_ERR_FLAG = True

        finally:
            sock.close()
            if not SOCK_ERR_FLAG:
                results['SCAN_RESULT'] = 1
                results['SCAN_RESULT_DESC'] = 'Success'
            else:
                results['SCAN_RESULT'] = -1
                results['SCAN_RESULT_DESC'] = 'Socket error connecting to {0} on port {1}'.format(ip_address, dnp3_port)
            return results

def main():
    results = dnp3_read_analog_inputs(sys.argv[1],int(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4]))
    results_dict = json.dumps(results)
    print(results_dict)

if __name__ == '__main__':
    main()
