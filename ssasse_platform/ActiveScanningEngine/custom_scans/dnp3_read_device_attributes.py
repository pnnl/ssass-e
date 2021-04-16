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

#!/usr/bin/python3.6

import binascii
import os
import socket
import sys
import crcmod
import time
import itertools
import struct
import json
import logging

_log = logging.getLogger(__name__) 

CRC_Fun = crcmod.predefined.mkPredefinedCrcFun("crc-16-dnp")

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
    return ([e for e in t if e != None] for t in itertools.zip_longest(*args))


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

    try:
        #print('sending {!r}'.format(binascii.hexlify(req_info)))
        sock.connect(server_address)
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

    except Exception as error:
        _log.error("Not able to establish connection on port {} with {}: Socket Error: {}".format(port, ip, error))
        if str(error) != "[Errno 104] Connection reset by peer":
            SOCK_ERR_FLAG = True
    finally:
   #     print('closing socket')
        sock.close()
        return (DNP_COMS, SOCK_ERR_FLAG)

def dnp3_read_device_attributes(ip_address, dnp3_port, dnp3_master, dnp3_slave):
    #print("dnp3_read_device_attributes: {}".format(kwargs))

    #print "Got to dnp3_read_device_attributes"
    dnp3_data_link_header = [0x05, 0x64, 0x0e, 0xc4]

    dnp3_data_link_header.append(dnp3_slave & 0xff)
    dnp3_data_link_header.append(dnp3_slave >> 8)
    dnp3_data_link_header.append(dnp3_master & 0xff)
    dnp3_data_link_header.append(dnp3_master >> 8)

    dnp3_data = [0xc1, 0xc1, 0x01, 0x00, 0xfa, 0x06, 0x00, 0xfc, 0x06]

    #---------------MAIN--------------------

    #Calculate Checksums

    packed_dnp3_data_link_header = bytearray(struct.pack('B B B B B B B B', *dnp3_data_link_header))
    dnp3_data_link_checksum = CRC_Fun(bytes(packed_dnp3_data_link_header))
    packed_dnp3_data_link_header.append(dnp3_data_link_checksum & 0xff)
    packed_dnp3_data_link_header.append(dnp3_data_link_checksum >> 8)

    packed_dnp3_application_data = bytearray(struct.pack('B B B B B B B B B', *dnp3_data))
    dnp3_data_checksum = CRC_Fun(bytes(packed_dnp3_application_data))
    packed_dnp3_application_data.append(dnp3_data_checksum & 0xff)
    packed_dnp3_application_data.append(dnp3_data_checksum >> 8)


    #Build Packet Data
    req_info =  packed_dnp3_data_link_header + packed_dnp3_application_data

    #print "Before Request Link Status"

    retry_count = 2

    while retry_count > 0:

        time.sleep(10)
        DNP3_COMS, SOCK_ERR_FLAG = dnp3_request_link_status(dnp3_master, dnp3_slave, ip_address, dnp3_port)
        if DNP3_COMS == True or SOCK_ERR_FLAG == True:
            break
        retry_count -= 1

    #print "before results"
    results = dict.fromkeys(['TARGET_IPADDR', 'SCAN_NAME', 'DNP3_COMMS', 'DNP3_DATA_AVAILABLE', 'MODEL', 'VENDOR', 'SCAN_RESULT', 'SCAN_RESULT_DESC'])

    results['TARGET_IPADDR'] = ip_address
    results['SCAN_NAME'] = 'dnp3_read_device_attributes'
 
    if SOCK_ERR_FLAG == True:
        results['SCAN_RESULT'] = -1
        results['SCAN_RESULT_DESC'] = 'Socket error connecting to {0}:{1}'.format(ip_address, dnp3_port)
        return results
    #print "After Request Link Status"
    #Sleep to provide time for connection to close properly
    if DNP3_COMS == True:
        time.sleep(10)
    
    #Open connection
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (ip_address, dnp3_port)
    sock.settimeout(10)

    #Send packet and receive response

    #Check if DNP3 Communication is even possible

    if not DNP3_COMS:
        results['DNP3_COMMS'] = 0
        results['SCAN_RESULT'] = 0
        results['SCAN_RESULT_DESC'] = 'No Link Status returned from DNP3 slave at {0}. It is possible that the slave device does not accept the scanner as a master'.format(ip_address)
        return results
    else:
        results['DNP3_COMMS'] = 1

        try:
            #print('sending {!r}'.format(binascii.hexlify(req_info)))
            sock.connect(server_address)
            sock.sendall(req_info)
            res = sock.recv(1024)

            #Parse Packet
            crc_check = 0
            tmp_dnp_data = ""
            dnp3_response_no_crc = []
            tmp_dnp_data_counter = 0
            MODEL = ""
            man = ""

            if (res):
                length_offset = 2
                App_Internal_Indications_offset_1 = 13
                App_Internal_Indications_offset_2 = 14
                App_Object_Data_length_offset = 11

                for i in range(len(res)):
                    if res[i] == 0x05 and res[i+1] == 0x64:
                        if len(res) > 10: #Packet is not just a Request Link Status
                            tmp_dnp_data = res[10:]
                            tmp_dnp_data = list(mygrouper(18, bytearray(tmp_dnp_data)))
                            for l in tmp_dnp_data:
                                if len(l) == 18:
                                    dnp3_response_no_crc = dnp3_response_no_crc + l[:-2]
                                else:
                                    dnp3_response_no_crc = dnp3_response_no_crc + l
                            #for b in dnp3_response_no_crc:
                            #    sys.stdout.write(hex(b) + " ")
                            #sys.stdout.write("\n")
                            internal_indications_1 = res[i+App_Internal_Indications_offset_1]
                            internal_indications_2 = res[i+App_Internal_Indications_offset_2]
                            #TODO Add condition for each indication flag
                            if isNthBitSet(internal_indications_2, 2) or isNthBitSet(internal_indications_2, 3):
                                results['DNP3_DATA_AVAILABLE'] = 0
                                return results
                            #Checking for indication of class 1, 2, or 3 data available (This may not be a good indication that device attributes are in the response)
                            elif isNthBitSet(internal_indications_1, 2) or isNthBitSet(internal_indications_1, 3) or isNthBitSet(internal_indications_1, 4):
                                results['DNP3_DATA_AVAILABLE'] = 1

                                #look at byte 21 (byte 11 in dnp3_respone_no_crc) for length of object data, read next length bytes as object data, skip 7 more bytes after
                            #print(App_Object_Data_length_offset+dnp3_response_no_crc[App_Object_Data_length_offset])
                            #print(type(dnp3_response_no_crc[4]))
                            for j in range(App_Object_Data_length_offset+1, App_Object_Data_length_offset+dnp3_response_no_crc[App_Object_Data_length_offset]+1):
                                #sys.stdout.write(str(chr(dnp3_response_no_crc[j])))
                                MODEL += str(chr(dnp3_response_no_crc[j]))
                            #sys.stdout.write("\n")
                            App_Object_Data_length_offset = App_Object_Data_length_offset + dnp3_response_no_crc[App_Object_Data_length_offset] + 7
                            #print MODEL
                            for j in range(App_Object_Data_length_offset+1, App_Object_Data_length_offset+dnp3_response_no_crc[App_Object_Data_length_offset]+1):
                                #sys.stdout.write(chr(dnp3_response_no_crc[j]))
                                man += str(chr(dnp3_response_no_crc[j]))
                            #sys.stdout.write("\n")
                            #print man 

                results['MODEL'] = MODEL
                results['VENDOR'] = man

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
    results = dnp3_read_device_attributes(sys.argv[1],int(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4]))
    results_dict = json.dumps(results)
    print(results_dict)

if __name__ == '__main__':
    main()
