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

from __future__ import division
from __future__ import absolute_import
from utils import web_sigs, telnet_sigs
import binascii
import subprocess
import os
import socket
import struct
import sys
import ctypes
import crcmod
import time
import itertools
from pymodbus.client.sync import ModbusTcpClient as ModbusClient
import logging
#_log = logging.getLogger(__name__)
import json
from ftplib import FTP
import telnetlib
import json
import string
import ssl
from datetime import datetime
import urllib.request
from fuzzywuzzy import fuzz
from fuzzywuzzy import process
import requests
import tftpy
import re
from crccheck.crc import CrcArc
import psycopg2
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
    return ([e for e in t if e != None] for t in itertools.izip_longest(*args))

def SEL_Relay_get_DeviceInfo(**kwargs):
    """
    This function pulls the relevant device information and returns a dictionary.
    """
    IP=kwargs['TARGET_IPADDR']
    PORT=int(kwargs['TARGET_PORT'])

    return_results = dict.fromkeys(['TARGET_IPADDR', 'SCAN_NAME', 'MODEL', 'IEC_61850_DEVICE_CONFIG_VERSION', 'DEVICE_CODE', 'IEC_61850_CID_VERSION', 'PART_NO', 'SERIAL_NO', 'DEVICE_NAME', 'IEC_61850_DEVICE_NAME', 'BOOT_FIRMWARE_ID', 'DEVICE_CONFIG_ID', 'FIRMWARE_ID', 'DEVICE_SPECIAL'])
    return_results['SCAN_NAME'] = 'SEL_Relay_get_DeviceInfo'
    return_results['TARGET_IPADDR'] = kwargs['TARGET_IPADDR']
 

    try:
        tn=telnetlib.Telnet(IP, PORT)
        tn.write(b'ID\r\n')
        time.sleep(5)
        tn.write(b'HEL\r\n')
        tn.write(b'EXI\r\n')
        # Read all the output from the telnet session
        output=tn.expect([re.compile(b'EXI\r\n')])[2].decode('ascii')
        tn.close()
        # Parse the output results
        output=output[output.find("\"")+1:output.rfind("\"")]

        outSplit=output.split("\",\"")
        i=0
        # Trim out a part of the response that is not needed
        for substr in outSplit:
            outSplit[i]=substr[substr.find("\n")+2:]
            i+=1
        # Remove the last element in the list as it is not needed
        outSplit.pop()
        # Now we need to convert this list into a dictionary
        results={}
        for item in outSplit:
            left=item.find('=')
            attribute=item[0:left]
            results[attribute]=item[left+1:]
            print(item)
    except socket.error as e:
        _log.error("SEL_Relay_get_DeviceInfo: Socket Error, Could not create telnet session on {}:{}".format(IP, PORT))
        return return_results
        

    _log.debug("SEL_Relay_get_DeviceInfo: {}".format(results))
    return_results['MODEL'] = results.get('type') 
    return_results['IEC_61850_DEVICE_CONFIG_VERSION'] = results.get('configVersion')
    return_results['DEVICE_CODE'] = results.get('DEVCODE')
    return_results['IEC_61850_CID_VERSION'] = results.get('CID')
    return_results['PART_NO'] = results.get('PARTNO')
    return_results['SERIAL_NO'] = results.get('SERIALNO')
    return_results['DEVICE_NAME'] = results.get('DEVID')
    return_results['IEC_61850_DEVICE_NAME'] = results.get('iedName')
    return_results['BOOT_FIRMWARE_ID'] = results.get('BFID')
    return_results['DEVICE_CONFIG_ID'] = results.get('CONFIG')
    return_results['FIRMWARE_ID'] = results.get('ID')
    return_results['DEVICE_SPECIAL'] = results.get('SPECIAL')

    return return_results

def SEL_Lantronix_get_DeviceInfo(**kwargs):
    """
    This function pulls the relevant device information and returns a dictionary.
    """
    IP=kwargs['TARGET_IPADDR']
    PORT=int(kwargs['TARGET_PORT'])

    return_results = dict.fromkeys(['TARGET_IPADDR', 'SCAN_NAME', 'MODEL', 'IEC_61850_DEVICE_CONFIG_VERSION', 'DEVICE_CODE', 'IEC_61850_CID_VERSION', 'PART_NO', 'SERIAL_NO', 'DEVICE_NAME', 'IEC_61850_DEVICE_NAME', 'BOOT_FIRMWARE_ID', 'DEVICE_CONFIG_ID', 'FIRMWARE_ID', 'DEVICE_SPECIAL'])
    return_results['SCAN_NAME'] = 'SEL_Relay_get_DeviceInfo'
    return_results['TARGET_IPADDR'] = kwargs['TARGET_IPADDR']
 

    try:
        tn=telnetlib.Telnet(IP, PORT)
        tn.write(b'ID\r\n')
        time.sleep(5)
        tn.write(b'HEL\r\n')
        # Read output from the session
        output=tn.read_until(b"*", 5).decode('ascii')

        # Parse the output results
        output=output[output.find("\"")+1:output.rfind("\"")]

        outSplit=output.split("\",\"")
        i=0
        # Trim out a part of the response that is not needed
        for substr in outSplit:
            outSplit[i]=substr[substr.find("\n")+2:]
            i+=1
        # Remove the last element in the list as it is not needed
        outSplit.pop()
        # Now we need to convert this list into a dictionary
        results={}
        for item in outSplit:
            left=item.find('=')
            attribute=item[0:left]
            results[attribute]=item[left+1:]
            print(item)
    except socket.error as e:
        _log.error("SEL_Relay_get_DeviceInfo: Socket Error, Could not create telnet session on {}:{}".format(IP, PORT))
        return return_results
        

    _log.debug("SEL_Relay_get_DeviceInfo: {}".format(results))
    return_results['MODEL'] = results.get('type') 
    return_results['IEC_61850_DEVICE_CONFIG_VERSION'] = results.get('configVersion')
    return_results['DEVICE_CODE'] = results.get('DEVCODE')
    return_results['IEC_61850_CID_VERSION'] = results.get('CID')
    return_results['PART_NO'] = results.get('PARTNO')
    return_results['SERIAL_NO'] = results.get('SERIALNO')
    return_results['DEVICE_NAME'] = results.get('DEVID')
    return_results['IEC_61850_DEVICE_NAME'] = results.get('iedName')
    return_results['BOOT_FIRMWARE_ID'] = results.get('BFID')
    return_results['DEVICE_CONFIG_ID'] = results.get('CONFIG')
    return_results['FIRMWARE_ID'] = results.get('ID')
    return_results['DEVICE_SPECIAL'] = results.get('SPECIAL')

    return return_results

def SAGE_Relay_get_DeviceInfo(**kwargs):
    """
    This function pulls the relevant device information and returns a dictionary.
    """
    deviceIP=kwargs['TARGET_IPADDR']
    default_creds=['Admin','Admin']
    try:
        ftp=FTP(deviceIP)
        ret_code=ftp.login(user=default_creds[0],passwd=default_creds[1])
        #print(ret_code)
    except Exception as err:
        print('Login exception: ',err)

    # If we are able to login into the device with the default credentials,
    # Then, let us try to download key files from its file system
    try:
        fileNames=['access.xml','bootline.xml']
        for f in fileNames:
            fd=open(f,'wb')
            ret_code=ftp.retrbinary('RETR '+ f,fd.write)
            fd.close()
            #print(ret_code)
    except Exception as err:
        print(ret_code,': ',err)
    # Now, we pull the file that has info on the MODEL, OS, etc.,
    # We will try to cd into Webfiles/xml
    try:
        ret_code=ftp.cwd('/d:/Webfiles/xml/')
        #print(ret_code)
        fileNames=['rtusetup.xml']
        for f in fileNames:
            fd=open(f,'wb')
            ret_code=ftp.retrbinary('RETR '+ f,fd.write)
            fd.close()
            #print(ret_code)
    except Exception as err:
        print('Exception when trying to read RTU configuration!')
    ftp.quit()

    # If the files are available, then let us read it back first,
    # and store it in a format that is useful
    try:
        # Bootline gives us some information about which file is used to boot
        # and the IP address, netmask, gateway

        f='bootline.xml'
        results={}
        fd=open(f,'r')
        for line in fd:
            words=line.split(' ')
            for word in words:
                if len(word)==0:
                    continue
                if word[0]=='e':
                    results['IPADDR:NETMASK']=word[3:len(word)-1]
                elif word[0]=='g':
                    results['GATEWAY']=word[3:len(word)-4]
        fd.close()
        # RTU Setup has all the important information
        f='rtusetup.xml'
        fd=open(f,'r')
        copy=0
        # We need to parse the XML file to get the information
        # Here we find the RTU section and get the fields underneath that
        for line in fd:
            if line.find('<RTU>')==0:
                copy=1
            elif line.find('</RTU>')==0:
                copy=0
            if copy:
                if line[1]=='/':
                    continue
                left=line.find('>')
                right=line.rfind('<')
                attribute=line[1:left]
                if (right-left)>0:
                    value=line[left+1:right]
                else:
                    continue
                results[attribute]=value
        fd.close()
        os.remove('access.xml')
        os.remove('bootline.xml')
        os.remove('rtusetup.xml')

        return_results = {}

        return_results['SCAN_NAME'] = 'SAGE_Relay_get_DeviceInfo'
        return_results['TARGET_IPADDR'] = kwargs['TARGET_IPADDR']
        return_results['DEVICE_MISC'] = results['APPFILE']
        return_results['DEVICE_NAME'] = results['NAME']
        return_results['FIRMWARE_DATE'] = results['VXCREATED']
        return_results['PART_NO'] = results['PARTNO']
        return_results['DEVICE RUN MODE'] = results['RUNMODE']
        return_results['FIRMWARE_ID'] = results['VXVERSION']
        return_results['MODEL'] = results['TYPE']
        return_results['TARGET_GATEWAY_IPADDR'] = results['GATEWAY']
        return_results['TARGET_NETMASK'] = results['IPADDR:NETMASK'].split(':')[1]
        return return_results

    except Exception as err:
        print('Something went wrong with the file parsing!')

class configMgmtGE(object):

    def __init__(self,ipAddress,port=502):
        """
        Modbus initialization.
        """
        self.ipAddress=ipAddress
        self.port=port
        self.slaveAddress=0x0
        self.IPAddress='0.0.0.0'
        self.gatewayIPAddress='0.0.0.0'
        self.subnetMask='255.255.0.0'
    
    def detectSlaveID(self):
        """
        Detect the slave ID for sweeping through Modbus addresses 1-254.
        """
        client = ModbusClient(self.ipAddress,self.port)
        client.connect()
        
        for UNIT in range(0,255):
            try:
                rr = client.read_input_registers(0, 1, unit=UNIT)
                if (rr.isError()):
                    pass
                else:
                    self.slaveAddress=UNIT
                    break
            except Exception as e:
                print(str(e))
                pass
        client.close()
        return self
    
    def getDeviceInfo(self):
        """
        Get all the important device parameters that are relevant for SSASS-E.
        """
        client = ModbusClient(self.ipAddress,self.port)
        client.connect()

        # Product Type - 0x00, one 16 bit unsigned integer
        rr = client.read_input_registers(0x00, 1, unit=self.slaveAddress)
        if (not rr.isError()):
            self.productType=rr.registers[0]

        # Product Version - 0x02, one 16 bit unsigned integer
        rr = client.read_input_registers(0x02, 1, unit=self.slaveAddress)
        if (not rr.isError()):
            self.productVersion=rr.registers[0]/100
        
        # Serial Number - 0x10, 16 character ASCII Text
        rr = client.read_input_registers(0x10, 6, unit=self.slaveAddress)
        if (not rr.isError()):
            self.serialNumber=self.convertF203(rr.registers)
        
        # Part Number - 0x40, 80 character ASCII Text
        rr = client.read_input_registers(0x40, 18, unit=self.slaveAddress)
        if (not rr.isError()):
            self.partNumber=self.convertF204(rr.registers)
        
        # Ethernet MAC Address - 0x90, Hex 6 Bytes ASCII Text
        rr = client.read_input_registers(0x90, 3, unit=self.slaveAddress)
        if (not rr.isError()):
            self.MACAddress=self.convertF072MAC(rr.registers)
        
        # CPU Module Serial Number - 0xA0, 16 character ASCII Text
        rr = client.read_input_registers(0xA0, 6, unit=self.slaveAddress)
        if (not rr.isError()):
            self.CPUSerialNumber=self.convertF203(rr.registers)
        
        # CPU Supplier Serial Number - 0xB0, 16 character ASCII Text
        rr = client.read_input_registers(0xB0, 7, unit=self.slaveAddress)
        if (not rr.isError()):
            self.CPUSupplierSerialNumber=self.convertF203(rr.registers)
        
        # Ethernet Sub Module Serial Number - 0xC0, 16 character ASCII Text
        rr = client.read_input_registers(0xC0, 7, unit=self.slaveAddress)
        if (not rr.isError()):
            self.EthernetSerialNumber=self.convertF203(rr.registers)
        
        client.close()
        return self

    def getIPConfig(self):
        """
        Read the IP address, subnet mask, gateway of a GE UR relay over Modbus.
        """
        client = ModbusClient(self.ipAddress,self.port)
        client.connect()
        
        # Read the IP address first
        rr = client.read_input_registers(0x4087, 2, unit=self.slaveAddress)
        if (not rr.isError()):
            self.IPAddress=self.convertF072IP(rr.registers)

        # Read the Subnet mask then
        rr = client.read_input_registers(0x4089, 2, unit=self.slaveAddress)
        if (not rr.isError()):
            self.subnetMask=self.convertF072IP(rr.registers)
        
        # Read the Gateway IP address last
        rr = client.read_input_registers(0x408B, 2, unit=self.slaveAddress)
        if (not rr.isError()):
            self.gatewayIPAddress=self.convertF072IP(rr.registers)
        
        client.close()
        return self

    def getSCADAConfig(self):
        """
        Read the addresses for Modbus, DNP3 protocols of a GE UR relay over Modbus.
        """
        client = ModbusClient(self.ipAddress,self.port)
        client.connect()
        
        # Read the Modbus slave address 
        rr = client.read_input_registers(0x4080, 1, unit=self.slaveAddress)
        if (not rr.isError()):
            self.ModbusSlaveAddress=rr.registers[0]

        # Read the Modbus port number
        rr = client.read_input_registers(0x40A3, 1, unit=self.slaveAddress)
        if (not rr.isError()):
            self.ModbusPortNumber=rr.registers[0]

        # Read the DNP3 slave address
        rr = client.read_input_registers(0x409C, 1, unit=self.slaveAddress)
        if (not rr.isError()):
            self.DNP3SlaveAddress=rr.registers[0]
        
        # Read the DNP3 port number
        rr = client.read_input_registers(0x40A4, 1, unit=self.slaveAddress)
        if (not rr.isError()):
            self.DNP3PortNumber=rr.registers[0]
        
        client.close()
        return self
    
    def changeIPAddress(self):
        """
        Set the IP address of a GE UR relay over Modbus.
        """
        return self
    
    def convertF203(self,words):
        """
        Convert GE configuration format F203 to a readble output.
        """
        Out=''
        for word in words:
            for byte in word.to_bytes(2, byteorder='big'):
                Out+=chr(byte)
        return Out

    def convertF204(self,words):
        """
        Convert GE configuration format F204 to a readble output.
        """
        Out=''
        counter=0
        for word in words:
            for byte in word.to_bytes(2, byteorder='big'):
                Out+=chr(byte)
        return Out[:len(Out)-1]

    def convertF072IP(self,words):
        """
        Convert GE configuration format F072 to a readble output.
        """
        IP=''
        for word in words:
            for byte in word.to_bytes(2, byteorder='big'):
                IP+=str(byte)+'.'
        return IP[:len(IP)-1]

    def convertF072MAC(self,words):
        """
        Convert GE configuration format F072 to a readble output.
        """
        MAC=''
        for word in words:
            for byte in word.to_bytes(2, byteorder='big'):
                if byte<15:
                    MAC+='0'
                MAC+=hex(byte)[2:]+'-'
        return MAC[:len(MAC)-1]

def dnp3_request_link_status(**kwargs):

    dnp3_data_link_header = [0x05, 0x64, 0x05, 0xc9]
    incorrect_dnp3_data_link_header = [0x05, 0x64, 0x05, 0xc9]
    ip_address = kwargs['TARGET_IPADDR']
    dnp3_slave = int(kwargs['DNP3_SLAVE_ID'])
    dnp3_master = int(kwargs['DNP3_MASTER_ID'])
    incorrect_dnp3_master = dnp3_master + 1

    incorrect_dnp3_data_link_header.append(dnp3_slave & 0xff)
    incorrect_dnp3_data_link_header.append(dnp3_slave >> 8)
    incorrect_dnp3_data_link_header.append(incorrect_dnp3_master & 0xff)
    incorrect_dnp3_data_link_header.append(incorrect_dnp3_master >> 8)

    dnp3_data_link_header.append(dnp3_slave & 0xff)
    dnp3_data_link_header.append(dnp3_slave >> 8)
    dnp3_data_link_header.append(dnp3_master & 0xff)
    dnp3_data_link_header.append(dnp3_master >> 8)

    req_info = bytearray(struct.pack('B B B B B B B B', *dnp3_data_link_header))
    incorrect_req_info = bytearray(struct.pack('B B B B B B B B', *incorrect_dnp3_data_link_header))

    incorrect_dnp3_data_link_checksum = CRC_Fun(bytes(incorrect_req_info))
    incorrect_req_info.append(incorrect_dnp3_data_link_checksum & 0xff)
    incorrect_req_info.append(incorrect_dnp3_data_link_checksum >> 8)

    dnp3_data_link_checksum = CRC_Fun(bytes(req_info))
    req_info.append(dnp3_data_link_checksum & 0xff)
    req_info.append(dnp3_data_link_checksum >> 8)

    dnp_port = int(kwargs['DNP3_PORT'])

#Open connection
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (ip_address, dnp_port)
    sock.settimeout(10)
#Send packet and receive response


    results = dict.fromkeys(['TARGET_IPADDR', 'SCAN_NAME', 'DNP3_COMMS', 'RESP_TO_ANY_DNP3_MASTER', 'SCAN_RESULT', 'SCAN_RESULT_DESC'])
    results['TARGET_IPADDR'] = ip_address
    results['SCAN_NAME'] = 'dnp3_request_link_status'

    try:
        #print('sending {!r}'.format(binascii.hexlify(req_info)))
        sock.connect(server_address)
        sock.sendall(req_info)
        res = sock.recv(1024)
        sock.sendall(incorrect_req_info)
        res2 = sock.recv(1024)

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
                    results['DNP3_COMMS']  = 1

        is_Status = 0
        crc_check = 0
        tmp_dnp_data = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        tmp_dnp_data_counter = 0

        if results['DNP3_COMMS'] == 1:
            if (res2):
                length_offset = 2
                DL_control_offset = 3

                for i in range(len(res2)):
                    if res2[i] == 0x05 and res2[i+1] == 0x64:
                        if res2[i+DL_control_offset] == 0x0b:
                            is_Status = 1
                            for j in range(i+int(res2[i+length_offset]) + 5):
                                tmp_dnp_data[tmp_dnp_data_counter] = res2[j]
                                tmp_dnp_data_counter += 1
                            tmp_dnp_data = bytearray(tmp_dnp_data) 
                        else:
                            is_Status = 0
        
                if is_Status == 1:
                    crc_check = check_crc(tmp_dnp_data, tmp_dnp_data_counter)
                    if crc_check == 0:
                        results['RESP_TO_ANY_DNP3_MASTER']  = 1

        results['SCAN_RESULT'] = 1
        results['SCAN_RESULT_DESC'] = 'Success'

    except socket.error as error:
        _log.error("dnp3_request_link_status: Socket Error, Could not create TCP session on {}:{}".format(ip_address, dnp_port))
        results['SCAN_RESULT'] = -1
        results['SCAN_RESULT_DESC'] = "Socket error occured: {}".format(error)
        #print("ERROR: Not able to establish connection on port {} with {}: Socket Error: {}".format(dnp_port, ip_address, error))

    finally:
   #     print('closing socket')
        sock.close()
        return results

def GE_get_IPConfig(**kwargs):
    
    obj=configMgmtGE(kwargs['TARGET_IPADDR'])
    obj.detectSlaveID()
    obj.getIPConfig()

    #config_path = os.path.join(os.getcwd(), "ssasse_platform", "ActiveScanningEngine", "custom_scans")

    #python3_command = "./" + config_path + "SSASSE_config_mgmt_GE_get_IPConfig.py " + str(kwargs['TARGET_IPADDR'])
    #process = subprocess.Popen(python3_command.split(), stdout=subprocess.PIPE)
    #output, error = process.communicate()

    #print output
    #json.loads(output)

        
    results = dict.fromkeys(['TARGET_IPADDR', 'SCAN_NAME', 'TARGET_NETMASK', 'TARGET_GATEWAY_IPADDR'])



    results['TARGET_IPADDR'] = kwargs['TARGET_IPADDR']
    results['SCAN_NAME'] = 'GE_get_IPConfig'
    results['TARGET_NETMASK'] = obj.subnetMask
    results['TARGET_GATEWAY_IPADDR'] = obj.gatewayIPAddress

    return results
    
def GE_get_SCADAConfig(**kwargs):

    obj=configMgmtGE(kwargs['TARGET_IPADDR'])
    obj.detectSlaveID()
    obj.getSCADAConfig()


    #config_path = os.path.join(os.getcwd(), "ssasse_platform", "ActiveScanningEngine", "custom_scans")
    #python3_command = "./" + config_path + "SSASSE_config_mgmt_GE_get_SCADAConfig.py " + str(kwargs['TARGET_IPADDR'])
    #process = subprocess.Popen(python3_command.split(), stdout=subprocess.PIPE)
    #output, error = process.communicate()

    results = dict.fromkeys(['TARGET_IPADDR', 'SCAN_NAME', 'MODBUS_SLAVE_ID', 'MODBUS_PORT', 'DNP3_SLAVE_ID', 'DNP3_PORT'])

    results['TARGET_IPADDR'] = kwargs['TARGET_IPADDR']
    results['SCAN_NAME'] = 'GE_get_SCADAConfig'
    results['MODBUS_SLAVE_ID'] = obj.ModbusSlaveAddress
    results['MODBUS_PORT'] = obj.ModbusPortNumber
    results['DNP3_SLAVE_ID'] = obj.DNP3SlaveAddress
    results['DNP3_PORT'] = obj.DNP3PortNumber

    return results

def byteConvASCII(a):
    output='0x'
    for c in a:
        b=int.from_bytes([c],'big')
        if b<16:
            output+='0'+hex(b)[2:]
        else:
            output+=hex(b)[2:]
    return output

def CWETH_get_DeviceInfo(**kwargs):

    """
    This function pulls the relevant device information and returns a dictionary.
    """
    deviceIP=kwargs['TARGET_IPADDR']
    results={}
    resList=[]
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.settimeout(10)
            udp_ip_port=(deviceIP,1594)
            dest=b'\xff'
            source=b'\xff'
            session=b'\xc0'
            sequence=b'\x00'
            cmdPrefix=b'\xd0\x07\xff\xff\xff\xff'
            cmdPostfix=[0x002000,0x002040,0x002060,0x0020e0,0x040600,0x012000,0x0120c0,0x0120e0]
            #cmd=b'\xd0\x07\xff\xff\xff\xff\x00\x04\x00'
            #cmd=b'\xd0\x07\xff\xff\xff\xff\x01\x0b\x00\x00\x20'
            crc=b'\x1d\x0f'
            for item in cmdPostfix:
                out=(item).to_bytes(3,'big')
                cmd=cmdPrefix+out
                length=bytes([len(cmd)+6])
                message=b'\x7d'+length+dest+source+session+sequence+cmd+crc
                #print(str(message))
                s.sendto(message,udp_ip_port)
                data,addr=s.recvfrom(1024)
                resList.append(data[7:])
                #print(str(data))
            # Now, we parse the list into the dictionary that we want
            results['SerialNumber']= byteConvASCII(resList[0][0:4])
            results['BaseType']=byteConvASCII(resList[0][4:6])
            results['DeviceName']=(resList[3][0:20]).decode('ascii').split('\n')[0]
            results['DateCode']=byteConvASCII(resList[3][28:30])
            results['FirmwareSerialNumber']=byteConvASCII(resList[5][0:4])
            results['ModuleType']=byteConvASCII(resList[5][4:8])
            results['Firmware Version']=byteConvASCII(resList[5][8:10])
            results['VendorName']=(resList[6][16:32]).decode('ascii').split('\x00')[0]
            results['FirmwareDate']=byteConvASCII(resList[7][0:6])

        return_results = dict.fromkeys(['TARGET_IPADDR', 'SCAN_NAME', 'SERIAL_NO', 'MODEL', 'DEVICE_NAME', 'DATE_CODE', 'BOOT_FIRMWARE_ID', 'PART_NO', 'FIRMWARE_ID', 'VENDOR', 'FIRMWARE_DATE'])

        return_results['TARGET_IPADDR'] = kwargs['TARGET_IPADDR']
        return_results['SCAN_NAME'] = 'CWETH_get_DeviceInfo'
        return_results['SERIAL_NO']= results['SerialNumber']
        return_results['MODEL'] = results['BaseType']
        return_results['DEVICE_NAME'] = results['DeviceName']
        return_results['DATE_CODE'] = results['DateCode']
        return_results['BOOT_FIRMWARE_ID'] = results['FirmwareSerialNumber']
        return_results['PART_NO'] = results['ModuleType']
        return_results['FIRMWARE_ID'] = results['Firmware Version']
        return_results['VENDOR'] = results['VendorName']
        return_results['FIRMWARE_DATE'] = results['FirmwareDate']

        return return_results

    except Exception as err:
        #TODO: Make this a better error message
        print('Something went wrong!' + str(err))

def GE_Relay_get_DeviceInfo(**kwargs):

    obj=configMgmtGE(kwargs['TARGET_IPADDR'])
    obj.detectSlaveID()
    obj.getDeviceInfo()

    #config_path = os.path.join(os.getcwd(), "ssasse_platform", "ActiveScanningEngine", "custom_scans")
    #python3_command = config_path + "/"+ "SSASSE_config_mgmt_GE_Relay_get_DeviceInfo.py " + str(kwargs['TARGET_IPADDR'])
    #process = subprocess.Popen(python3_command.split(), stdout=subprocess.PIPE)
    #output, error = process.communicate()

    results = dict.fromkeys(['TARGET_IPADDR', 'SCAN_NAME', 'DEVICE_CODE', 'FIRMWARE_ID', 'SERIAL_NO', 'PART_NO', 'TARGET_MACADDR', 'TARGET_CPU_SERIAL_NO', 'TARGET_CPU_SUPPLIER_SERIAL_NO', 'TARGET_ETHERNET_SERIAL_NO'])

    results['TARGET_IPADDR'] = kwargs['TARGET_IPADDR']
    results['SCAN_NAME'] = 'GE_Relay_get_DeviceInfo'
    results['DEVICE_CODE'] = obj.productType
    results['FIRMWARE_ID'] = obj.productVersion
    results['SERIAL_NO'] = obj.serialNumber
    results['PART_NO'] = obj.partNumber
    results['MODEL'] = obj.partNumber[0:3]
    results['TARGET_MACADDR'] = obj.MACAddress
    results['TARGET_CPU_SERIAL_NO'] = obj.CPUSerialNumber
    results['TARGET_CPU_SUPPLIER_SERIAL_NO'] = obj.CPUSupplierSerialNumber
    results['TARGET_ETHERNET_SERIAL_NO'] = obj.EthernetSerialNumber

    return results

def dnp3_read_device_attributes(**kwargs):
    
    config_path = os.path.join(os.getcwd(), "ssasse_platform", "ActiveScanningEngine", "custom_scans")

    python3_command = "python3 " + config_path + "/" + "dnp3_read_device_attributes.py " + str(kwargs['TARGET_IPADDR']) + " " +  str(kwargs['DNP3_PORT']) + " " + str(kwargs['DNP3_MASTER_ID']) + " " + str(kwargs['DNP3_SLAVE_ID'])
    process = subprocess.Popen(python3_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()

    results = dict.fromkeys(['TARGET_IPADDR', 'SCAN_NAME', 'DNP3_COMMS', 'DNP3_DATA_AVAILABLE', 'MODEL', 'VENDOR', 'SCAN_RESULT', 'SCAN_RESULT_DESC'])
    
    results['SCAN_RESULT'] = json.loads(output.rstrip())['SCAN_RESULT']
    results['SCAN_RESULT_DESC'] = json.loads(output.rstrip())['SCAN_RESULT_DESC']
    results['TARGET_IPADDR'] = kwargs['TARGET_IPADDR']
    results['SCAN_NAME'] = 'dnp3_read_device_attributes'
    results['DNP3_COMMS'] = json.loads(output.rstrip())['DNP3_COMMS']
    results['DNP3_DATA_AVAILABLE'] = json.loads(output.rstrip())['DNP3_DATA_AVAILABLE']
    results['MODEL'] = json.loads(output.rstrip())['MODEL']
    results['VENDOR'] = json.loads(output.rstrip())['VENDOR']

    return results
 

def dnp3_read_analog_inputs(**kwargs):

    config_path = os.path.join(os.getcwd(), "ssasse_platform", "ActiveScanningEngine", "custom_scans")

    python3_command = "python3 " + config_path + "/" + "dnp3_read_analog_inputs.py " + str(kwargs['TARGET_IPADDR']) + " " +  str(kwargs['DNP3_PORT']) + " " + str(kwargs['DNP3_MASTER_ID']) + " " + str(kwargs['DNP3_SLAVE_ID'])
    process = subprocess.Popen(python3_command.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

    #print output

    results = dict.fromkeys(['TARGET_IPADDR', 'SCAN_NAME', 'DNP3_COMMS', 'MULTIPLE_ANINP_OBJ', 'DEFAULT_ANINP_VAR', 'SCAN_RESULT', 'SCAN_RESULT_DESC'])


    results['SCAN_RESULT'] = json.loads(output.rstrip())['SCAN_RESULT']
    results['SCAN_RESULT_DESC'] = json.loads(output.rstrip())['SCAN_RESULT_DESC']
    results['TARGET_IPADDR'] = kwargs['TARGET_IPADDR']
    results['SCAN_NAME'] = 'dnp3_read_analog_inputs'
    results['DNP3_COMMS'] = json.loads(output.rstrip())['DNP3_COMMS']
    results['MULTIPLE_ANINP_OBJ'] = json.loads(output.rstrip())['MULTIPLE_ANINP_OBJ']
    results['DEFAULT_ANINP_VAR'] = json.loads(output.rstrip())['DEFAULT_ANINP_VAR']

    return results

def h2bin(h):
  b = bytes.fromhex(h.translate({ord(c): None for c in string.whitespace}))
  return b

def get_ssl_cert(**kwargs):
  hello = """
  00 00 00 08 04 d2 16 2f
  """
  hello = h2bin(hello)
  sockaddr = (kwargs['TARGET_IPADDR'], kwargs['TARGET_PORT'],)

  context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
  context.options &= ~ssl.OP_NO_SSLv3
  context.check_hostname = False
  context.verify_mode = ssl.CERT_NONE
  not_before_date = None
  not_after_date = None

  results = dict.fromkeys(['TARGET_IPADDR', 'SCAN_NAME', 'SSL_CERT_NOT_BEFORE_DATE', 'SSL_CERT_NOT_AFTER_DATE', 'SSL_CERT_ISSUER', 'SSL_CERT_SUBJECT', 'VENDOR', 'MODEL', 'SCAN_RESULT', 'SCAN_RESULT_DESC'])
  results['TARGET_IPADDR'] = kwargs['TARGET_IPADDR']
  results['SCAN_NAME'] = 'get_ssl_cert'

  try:
      with socket.create_connection(sockaddr, timeout=10.) as sock:
        sock.send(hello)
        response = sock.recv(1)
        with context.wrap_socket(sock, do_handshake_on_connect=False) as ssock:
          ssock.do_handshake()
          cert = ssock.getpeercert(binary_form=True)
      server_cert = subprocess.check_output(('openssl', 'x509', '-inform', 'DER', '-text'), input=cert)
      for word in server_cert.decode('utf-8').split('\n'):
        if 'Issuer:' in word:
          results['SSL_CERT_ISSUER'] = str(word).split(':', 1)[1].strip()
          if 'SEL-3530 RTAC' in word:
             results['MODEL'] = 'SEL-3530 RTAC'
             results['VENDOR'] = 'SEL'
        if 'Subject:' in word:
          results['SSL_CERT_SUBJECT'] = str(word).split(':', 1)[1].strip()
        if 'Not Before:' in word:
          results['SSL_CERT_NOT_BEFORE_DATE'] = str(word).split(':', 1)[1].strip()
          not_before_date = datetime.strptime(str(word).split(':', 1)[1].strip(), '%b %d %H:%M:%S %Y %Z')
        if 'Not After :' in word:
          results['SSL_CERT_NOT_AFTER_DATE'] = str(word).split(':', 1)[1].strip()
          not_after_date = datetime.strptime(str(word).split(':', 1)[1].strip(), '%b %d %H:%M:%S %Y %Z')
        if not_before_date != None and not_after_date != None:
          results['SSL_CERT_VALID_DELTA'] = (not_after_date - not_before_date).days

      results['SCAN_RESULT'] = 1
      results['SCAN_RESULT_DESC'] = 'Success'
  except socket.error as error:
      _log.error("get_ssl_cert: Socket Error, Could not create TCP session on {}:{}".format(kwargs['TARGET_IPADDR'], kwargs['TARGET_PORT'] ))
      results['SCAN_RESULT'] = -1
      results['SCAN_RESULT_DESC'] = "Socket error occured: {}".format(error)
      #print("ERROR: Not able to establish connection on port {} with {}: Socket Error: {}".format(dnp_port, ip_address, error))

  finally:
  #     print('closing socket')
    sock.close()
    return results


  #TODO: Do something with this info: ie. if self signed cert maybe we start to assume the targets don't vary from defaults often
  #if results['SSL_CERT_ISSUER'] == 'C=US, ST=Washington, L=Pullman, O=Schweitzer Engineering Laboratories, Inc., OU=Automation and Integration Engineering, CN=SEL-3530 RTAC' and results['SSL_CERT_ISSUER'] == results['SSL_CERT_SUBJECT']:
  #    print("Found SEL 3530 with SELF SIGNED CERT")
   

def scrape_http_server(**kwargs):

    if kwargs['TARGET_PORT'] == 80:
        url = "http://" + str(kwargs['TARGET_IPADDR'])
    else:
        url = "http://" + str(kwargs['TARGET_IPADDR'] + ":" + str(kwargs['TARGET_PORT']))

    results = dict.fromkeys(['TARGET_IPADDR', 'SCAN_NAME', 'VENDOR', 'MODEL', 'FIRMWARE_ID', 'SCAN_RESULT', 'SCAN_RESULT_DESC'])
    results['TARGET_IPADDR'] = kwargs['TARGET_IPADDR']
    results['SCAN_NAME'] = 'scrape_http_server'

    try:
        html = urllib.request.urlopen(url)
        resp = html.read()
    except socket.error as e:
        _log.error("Socket error connecting to http server of remote device: {}".format(e))
        results['SCAN_RESULT'] = -1
        results['SCAN_RESULT_DESC'] = "Could not connect to HTTP server on {} port {}".format(kwargs['TARGET_IPADDR'], kwargs['TARGET_PORT'])
        return results

    if fuzz.ratio(web_sigs['SAGE_3600_SPLASH_PAGE'], resp) > 80:
        results['VENDOR'] = 'schneider'
        results['MODEL'] = 'SAGE 3600'

    if fuzz.ratio(web_sigs['SEL_RELAY_SPLASH_PAGE'], resp) > 80 or 'Schweitzer Engineering Laboratories, Inc.' in str(resp):
        results['VENDOR'] = 'SEL'
    if fuzz.ratio(web_sigs['SIE7UT61_SPLASH_PAGE'], resp) > 80:
        results['VENDOR'] = 'siemens'
        results['MODEL'] = 'SIE7UT613'
    if fuzz.ratio(web_sigs['SIE7SJ64_SPLASH_PAGE'], resp) > 80:
        results['VENDOR'] = 'siemens'
        results['MODEL'] = 'SIE7SJ64'
    if fuzz.ratio(web_sigs['GE_RELAY_SPLASH_PAGE'], resp) > 80:
        results['VENDOR'] = 'GE'
        if 'D30 Distance Relay' in str(resp):
            results['MODEL'] = 'D30'
        elif 'L90 Line Relay' in str(resp):
            results['MODEL'] = 'L90'
        elif 'N60 Network Relay' in str(resp):
            results['MODEL'] = 'N60'
        elif 'T60 TransformerRelay' in str(resp):
            results['MODEL'] = 'T60'
        if 'Revision   ' in str(resp):
            tmp = str(resp).partition('Revision   ')[2]
            tmp2 = tmp.partition('<')[0]
            results['FIRMWARE_ID'] = str(tmp2)

    results['SCAN_RESULT'] = 1
    results['SCAN_RESULT_DESC'] = "Success"
    return results


def scrape_https_server(**kwargs):

    if kwargs['TARGET_PORT'] == 443:
        url = "https://" + str(kwargs['TARGET_IPADDR'])
    else:
        url = "https://" + str(kwargs['TARGET_IPADDR'] + ":" + str(kwargs['TARGET_PORT']))

    results = dict.fromkeys(['TARGET_IPADDR', 'SCAN_NAME', 'VENDOR', 'MODEL', 'SCAN_RESULT', 'SCAN_RESULT_DESC'])
    results['TARGET_IPADDR'] = kwargs['TARGET_IPADDR']
    results['SCAN_NAME'] = 'scrape_https_server'

    try:
    
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.options &= ~ssl.OP_NO_SSLv3
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        response = opener.open(url, data=None)

        resp = response.read()
    except socket.error as e:
        _log.error("Socket error connecting to https server of remote device: {}".format(e))
        results['SCAN_RESULT'] = -1
        results['SCAN_RESULT_DESC'] = "Could not connect to HTTPS server on {} port {}".format(kwargs['TARGET_IPADDR'], kwargs['TARGET_PORT'])
        return results

    identity_found = False

    if 'Schweitzer Engineering Laboratories, Inc.' in str(resp):
        results['VENDOR'] = 'SEL'
        identity_found = True
    if fuzz.ratio(web_sigs['RTAC_SPLASH_PAGE'], resp) > 80:
        identity_found = True
        results['MODEL'] = 'SEL 3530'
        if results['VENDOR'] == None:
            results['VENDOR'] = 'SEL'
    if fuzz.ratio(web_sigs['Lantronix_SLC32'], resp) > 80:
        identity_found = True
        results['VENDOR'] = 'Lantronix'
        if 'Lantronix SLC32' in str(resp):
            results['MODEL'] = 'SLC03212N-03'

    if identity_found == True:
        results['SCAN_RESULT'] = 1
        results['SCAN_RESULT_DESC'] = 'Success'
    else:
        results['SCAN_RESULT'] = 0
        results['SCAN_RESULT_DESC'] = "No HTTPS signature for device"

    return results

def FTP_default_cred_Check(**kwargs):
    """
    This is a function to check if a device allows anonymous FTP logins or if default credentials are being used.
    """
    results={}
    deviceIP=kwargs['TARGET_IPADDR']
    results['SCAN_NAME']='FTP_default_cred_Check'
    results['TARGET_IPADDR']=deviceIP
    results['TARGET_PORT']=kwargs['TARGET_PORT']
    results['FTP_ANONYMOUS']='N'
    results['FTP_DEFAULT_CREDS']='N'
    cred_list=[['','']]
    for key in kwargs.keys():
        if key=='DEFAULT_CREDS':
            cred_list.append(kwargs['DEFAULT_CREDS'])
        
        if key =='TARGET_PORT':
            target_port=kwargs['TARGET_PORT']
            results['TARGET_PORT']=target_port
        else:
            target_port=21
            results['TARGET_PORT']=target_port
    
    # Now we check the list
    for cred in cred_list:
        try:
            ftp=FTP()
            ftp.connect(deviceIP,port=target_port)
            ret_code=ftp.login(user=cred[0],passwd=cred[1])
            _log.debug(ret_code)
            ftp.quit()
            if(ret_code and cred[0]!=''):
                results['FTP_DEFAULT_CREDS']='Y'
            else:
                results['FTP_ANONYMOUS']='Y'
        except Exception as err:
            if (cred[0]!=''):
                results['FTP_DEFAULT_CREDS']='N'
            else:
                results['FTP_ANONYMOUS']='N'
            _log.debug('Exception in FTP login: '+str(err))
    return results

def TELNET_default_cred_Check(**kwargs):
    """
    This is a function to check if a device uses default credentials for TELNET.
    """
    results={}
    deviceIP=kwargs['TARGET_IPADDR']
    results['SCAN_NAME']='TELNET_default_cred_Check'
    results['TARGET_IPADDR']=deviceIP
    results['TARGET_PORT']=kwargs['TARGET_PORT']    
    results['TELNET_NO_PASSWORD']='N'
    results['TELNET_DEFAULT_CREDS']='N'
    cred_list=[]
    vendor='Generic'
    for key in kwargs.keys():
        if key == 'VENDOR':
            vendor=kwargs['VENDOR']
            if (cred_list==[]):
                if (vendor=='SEL'):
                    cred_list=[['ACC','OTTER'],['2AC','TAIL']]
                elif (vendor=='GE'):
                    cred_list=[['westronic','rd']]
        # Override default ports if supplied
        if key == 'TARGET_PORT':
            target_port=kwargs['TARGET_PORT']
        else:
            target_port=23
        # Override if we have credentials supplied
        if key=='DEFAULT_CREDS':
            default_creds=kwargs['DEFAULT_CREDS']
            cred_list=[default_creds]
        
    for cred in cred_list:
        try:
            cred[0]+='\r\n'
            cred[1]+='\r\n'
            # Connect to the device via Telnet
            tn=telnetlib.Telnet(deviceIP,port=target_port)
            # Enter the username first and proceed based on the response
            tn.write(b'\r\n')
            tn.write(cred[0].encode())
            time.sleep(0.1)
            # Take specific actions based on the device vendor
            if (vendor == 'SEL'):
                output=tn.read_until(b'random',1).decode('ascii')
                # Some devices do not need any password
                if (output.find('Invalid Access Level')!=-1):
                    results['TELNET_DEFAULT_CREDS']='N'
                # If we do not match the username then default creds are not used
                elif (output.find('Level 1')!=-1):
                    results['TELNET_NO_PASSWORD']='Y'
                    results['TELNET_DEFAULT_CREDS']='Y'
                # We proceed to enter the password if prompted
                elif (output.find('Password: ?')!=-1):
                    tn.write(cred[1].encode())
                    output=tn.read_until(b'random',1).decode('ascii')
                    # If we get a repeated password prompt, then the default creds are not used
                    if (output.find('Password: ?')!=-1):
                        results['TELNET_DEFAULT_CREDS']='N'
                    # If we succeed then we know default creds are used
                    elif (output.find('Level')!=-1):
                        results['TELNET_DEFAULT_CREDS']='Y'
            elif (vendor=='GE'):
                output=tn.read_until(b'random',1).decode('ascii')
                # We proceed to enter the password if prompted
                if (output.find('PASSWORD:')!=-1):
                    tn.write(cred[1].encode())
                    output=tn.read_until(b'random',1).decode('ascii')
                    # If we get a repeated username prompt, then the default creds are not used
                    if (output.find('USER NAME:')!=-1):
                        results['TELNET_DEFAULT_CREDS']='N'
                    else:
                        results['TELNET_DEFAULT_CREDS']='Y'
            else:
                output=tn.read_until(b'random',1).decode('ascii')
                tn.write(cred[1].encode())
                output=tn.read_until(b'random',1).decode('ascii')
                print(output)
                # If we get a repeated username prompt, then the default creds are not used
                words=['USER NAME:','Invalid','invalid','Incorrect','incorrect','login:','Password','password','failed']
                for word in words:
                    if (output.find(word)>=0):
                        results['TELNET_DEFAULT_CREDS']='N'
                        break
                    else:
                        results['TELNET_DEFAULT_CREDS']='Y'
            
            # Close the connection in the end
            tn.close()
            time.sleep(1)
        except Exception as err:
            print('Login exception: ',err)
            _log.debug('Exception in FTP login: '+str(err))
    return results

def SEL_HTTP_default_credential_Check(**kwargs):
    """
    This is a function to check the default credential to login into the HTTP server on a SEL relay.
    """
    try:
        # Get the inputs needed
        IP=kwargs['TARGET_IPADDR']
        creds=['','']
        for key in kwargs.keys():
                if key=='DEFAULT_CREDS':
                        creds=kwargs['DEFAULT_CREDS']
        # Initialize the results dictionary
        results={}
        results['TARGET_IPADDR']=IP
        results['SCAN_NAME']='SEL_HTTP_default_credential_Check'
        results['HTTP_DEFAULT_CREDS']='N'
        
        # Get the information from the appropriate page and parse it.
        url = 'http://'+IP+'/login'
        r = requests.post(url,verify=False,data={'pswd':creds[1]+'\r\n','usrid':creds[0],'rando':'3355343357'})
        resp=str(r.content)
        status=r.status_code

        if status==200 and resp.find('Invalid Password')<0:
            results['HTTP_DEFAULT_CREDS']='Y'
        return results
    except Exception as err:
        _log.debug('Exception in authenticating to the SEL relay\'s web page: '+str(err))
        results['HTTP_DEFAULT_CREDS']='Unknown'
        return results

def D20_TFTP_config_download(IP):
    try:
        fd=open('D20_config.txt','wb')
        obj=tftpy.TftpClient(IP,69)
        obj.download('NVRAM\*.UPL',fd)
        fd.close()
    except Exception as err:
        _log.debug('Exception in downloading the config file via TFTP!')

def trim_non_printable_char(word):
    trim_index=word.find(b'\x00')
    return word[:trim_index]

def D20_get_username_password(IP):
    """
    Function to download the D20 config via TFTP and get username and passwords.
    """
    # Initialize results
    results={}
    results['USERNAME']=''
    results['PASSWORD']=''
    results['CONTROL_PASSWORD']=''
       
    # Pull down the config file to parse it.
    D20_TFTP_config_download(IP)
    
    try:
        # We know the file name that we will get
        fd=open('D20_config.txt','rb')
        content=fd.read()
        fd.close()
        os.remove('D20_config.txt')
        
        # We find the location of the application that stores user configuration info
        file_cfg_start=content.find(b'B014USER')

        # We know that the username is at a fixed offset from the start of the application
        # We use that to extract the username, password, and control password successively
        username_start=file_cfg_start+242
        password_start=username_start+22
        control_password_start=password_start+22

        # Usernames and passwords have a max of 22 bytes, so we read in 22 bytes first and trim off invalid characters
        
        results['USERNAME']=trim_non_printable_char(content[username_start:password_start]).decode()
        results['PASSWORD']=trim_non_printable_char(content[password_start:control_password_start]).decode()
        results['CONTROL_PASSWORD']=trim_non_printable_char(content[control_password_start:control_password_start+23]).decode()
        return results
    except Exception as err:
        _log.debug('Exception in reading and parsing the D20 config file!')
        return results

def D20_RTU_get_device_info(**kwargs):
    """
    This is a function to get config information from a GE D20 RTU.
    """
    # Initializing results
    results={}
    deviceIP=kwargs['TARGET_IPADDR']
    results['SCAN_NAME']='D20_RTU_get_device_info'
    results['TARGET_IPADDR']=deviceIP
    results['MODEL']='Unknown'
    results['FIRMWARE_ID']='xxxxxx'
    results['PART_NO'] = 'xxxxxxxx'
    results['DEVICE_NAME'] = 'None'
    results['FIRMWARE_VERSION']='None'
    try:
        # First, we download the settings file from the D20's NVRAM over TFTP
        D20_TFTP_config_download(deviceIP)
        
        # We open this file to parse the results
        fd=open('D20_config.txt','rb')
        content=fd.read()
        fd.close()
        os.remove('D20_config.txt')
        
        # Now, we can parse the config file to populate the fields
        # Note: If there are multiple processors, this script will capture the details of only the first processor assuming it as the main processor.
        search_strings=[(b'FirmwareName=',b'\r\n','FIRMWARE_ID'),(b'FirmwareVer=',b'\r\n','FIRMWARE_VERSION'),(b'PartNumber=',b'\r\n','PART_NO'),(b'DeviceName=',b'\r\n','DEVICE_NAME')]
        for start,end,field in search_strings:
            split_resp=content.split(start)
            results[field]=split_resp[1].split(end)[0].decode()

        # We append firmware version to firmware id and delete firmware version
        results['FIRMWARE_ID']=results['FIRMWARE_ID']+'.'+results['FIRMWARE_VERSION']
        del results['FIRMWARE_VERSION']
        
        # Calculate model information based on part number
        if(results['PART_NO'].find('526-200')>=0):
            results['MODEL']='D20ME'
        # Now we search the file to identify serial devices under the D20
        # We look for Modbus and DNP applications in D20's firmware that have COM ports listed
        subres=D20_get_serial_devices(content)
        for key,value in subres.items():
            results[key]=value
        return results
    
    except Exception as err:
        _log.debug('Exception in getting the D20 device info: '+str(err))
    return results

def D20_get_serial_devices(content):
    """
    We search the content of the config file to identify serial devices under the D20
    We look for Modbus and DNP applications in D20's firmware that have COM ports listed
    """
    num_serial_DNP_devices=0
    num_serial_Modbus_devices=0
    results={}
    subresults={}
    results['SERIAL_DEVICES']={}

    try:
        if content.find(b'B013_CFG')>0 and content.find(b'B013_DEV')>0:
            search_area=content.split(b'B013_CFG')[1].split(b'B013_DEV')[0]
            search_results=re.findall(re.compile(b'(COM\d+)'),search_area)
            num_serial_DNP_devices=len(search_results)
            for entry in search_results:
                results['SERIAL_DEVICES'][entry.decode()]={'DEVICE_NAME':'Unknown','SERIAL_PROTOCOL':'DNP','MODEL':'Unknown','VENDOR':'Unknown'}
        
        if content.find(b'A059COM')>0 and content.find(b'A059SRU')>0:
            search_area=content.split(b'A059COM')[1].split(b'A059SRU')[0]
            search_results=re.findall(re.compile(b'(COM\d+)'),search_area)
            num_serial_Modbus_devices+=len(search_results)
            for entry in search_results:
                results['SERIAL_DEVICES'][entry.decode()]={'DEVICE_NAME':'Unknown','SERIAL_PROTOCOL':'Modbus','MODEL':'Unknown','VENDOR':'Unknown'}
        
        if content.find(b'A068COM')>0 and content.find(b'A068LRU')>0:
            search_area=content.split(b'A068COM')[1].split(b'A068LRU')[0]
            search_results=re.findall(re.compile(b'(COM\d+)'),search_area)
            num_serial_Modbus_devices+=len(search_results)
            for entry in search_results:
                results['SERIAL_DEVICES'][entry.decode()]={'DEVICE_NAME':'Unknown','SERIAL_PROTOCOL':'Modbus','MODEL':'Unknown','VENDOR':'Unknown'}
            
        results['NUM_SERIAL_DEVICES_CONNECTED']=num_serial_DNP_devices+num_serial_Modbus_devices
        return(results)
    except Exception as err:
        _log.debug('Exception in getting the info about serial devices: '+str(err))
        return results

def RTAC_get_temp_auth_token(IP):
    """
    This is a function to get a temporary authentication token for logging in to authenticate to the RTAC by visiting its home page.
    """
    try:
        url='http://'+IP+'/default.sel'
        r=requests.get(url,verify=False)
        resp=str(r.content)
        split_resp=resp.split('name="temp_auth_token" type="hidden" value="')
        split_resp=split_resp[1].split('" />\\n')
        temp_auth_token=split_resp[0]
        status=(r.status_code)
        if status==200:
            return temp_auth_token
        else:
            return '0'
    except Exception as err:
        _log.debug('Exception in loading the web page: '+str(err))
        return '0'

def RTAC_authenticate_get_session_id(IP,creds,temp_auth_token):
    """
    This is a function to login to the HTTPS server on the RTAC by visiting its authentication page.
    A successful login gives a session id that can be used later to get device information.
    """
    try:
        form_data={'session_username':creds[0],'password':creds[1],'auto_login':'true','temp_auth_token':temp_auth_token.encode()}
        url='http://'+IP+'/auth.sel'
        r=requests.post(url,verify=False,params=form_data)
        resp=r.content
        session_id=resp.decode()
        status=(r.status_code)
        # This returns a valid session id if the authentication is successful
        if status==200 and resp.find(b'ERROR: Login Failure')<0:
            return session_id
        else:
            return '0'
    except Exception as err:
        _log.debug('Exception in authenticating to the RTAC\'s web page: '+str(err))
        return '0'

def RTAC_RTU_get_Device_info(**kwargs):
    """
    This is a function to login to the HTTPS server and get device information.
    """
    try:
        # Get the inputs needed
        IP=kwargs['TARGET_IPADDR']
        creds=['admin','TAIL']
        for key in kwargs.keys():
            if key=='DEFAULT_CREDS':
                creds=kwargs['DEFAULT_CREDS']
        # Initialize the results dictionary
        results={}
        results['TARGET_IPADDR']=IP
        results['SCAN_NAME']='RTAC_RTU_get_Device_info'
        results['HOST_NAME']='None'
        results['DEVICE_LOCATION']='None'
        results['MODEL'] = 'None'
        results['SERIAL_NO'] = 'xxxxxxxx'
        results['DEVICE_NAME'] = 'None'
        results['FIRMWARE_ID'] = 'Rxxx'
        results['PROJECT_ID'] = 'xxxxxxxx'
        
        # Get the session id first after authenticating with the HTTPS server
        session_id=RTAC_authenticate_get_session_id(IP,creds,RTAC_get_temp_auth_token(IP))

        # Get the information from the appropriate page and parse it.
        url = 'https://'+IP+'/device_info.sel'
        r = requests.post(url,verify=False,params={'asfdasfowefsj':str(time.time())},data={'session_id':session_id,'session_username':creds[0]})
        resp=str(r.content)
        status=r.status_code
        if status==200 and resp.find('Your session has expired.')<0:
            # We parse it if the response is valid. Else, we return default dummy values.
            
            resp_search_strings=[('id="fid">','</td>','FIRMWARE_ID'),('id="project_id">','</td>','PROJECT_ID'),('id="serial_number">','</td>','SERIAL_NO'),('name="location" maxlength="255" value="','"/>\\n','DEVICE_LOCATION'),('id="host_name">','</td>','HOST_NAME'),('name="device_name" maxlength="255" value="','"/>\\n','DEVICE_NAME')]
            for start,end,field in resp_search_strings:
                split_resp=resp.split(start)
                results[field]=split_resp[1].split(end)[0]
            # we extract model information from the firmware id string
            results['MODEL']=results['FIRMWARE_ID'].split('-R')[0]
        # Now we try to get info about serial devices on the RTAC accessing a different web page
        subres=RTAC_get_serial_devices(IP,session_id,creds)
        for key,value in subres.items():
            results[key]=value
        
        return results
    except Exception as err:
        _log.debug('Exception in authenticating to the RTAC\'s web page: '+str(err))
        return results

def RTAC_get_serial_devices(IP,session_id,creds):
    """
    This is a function to get info about the serial devices connected to the RTAC.
    """
    results={}
    results['SERIAL_DEVICES']={}
    # Get the information from the appropriate page and parse it.
    try:
        url = 'https://'+IP+'/connected_ied_serial.sel'
        r = requests.post(url,verify=False,params={'asfdasfowefsj':str(time.time()),'count':'true','start':'1'},data={'session_id':session_id,'session_username':creds[0]})
        resp=r.content
        status=r.status_code
        if status!=200:
            return results
        #resp=serial_data_dump
        # Now we are searching through the response to extract the table data using regular expressions
        search_results=re.findall(re.compile(b'(<td>.*</td>)'),resp)

        # We know that the results are a table with the following fields
        # Protocol  RemoteDevice    Interface   Type	BaudRate   DataBits Parity     StopBits   Capture
        # We appropriate parse the list returned to put items in the respective keys in the dictionary
        
        # Just verifying to ensure that we have the results in the right format
        num_elements=len(search_results)
        if num_elements%9!=0:
            return results
        else:
            # Now we format and put the results in the right keys
            i=0
            while(i<=(num_elements-9)):
                protocol=search_results[i][4:len(search_results[i])-5].decode()
                device_name=search_results[i+1][4:len(search_results[i+1])-5].decode()
                interface=search_results[i+2][4:len(search_results[i+2])-5].decode()
                interface_type=search_results[i+3][4:len(search_results[i+3])-5].decode()
                baud_rate=search_results[i+4][4:len(search_results[i+4])-5].decode()
                i+=9
                model='Unknown'
                if protocol.find('SEL')>=0:
                    vendor='SEL'
                else:
                    vendor='Unknown'
                results['SERIAL_DEVICES'][interface]={'DEVICE_NAME':device_name,'SERIAL_PROTOCOL':protocol,'MODEL':model,'VENDOR':vendor,'INTERFACE_TYPE':interface_type,'BAUD_RATE':baud_rate}
        results['NUM_SERIAL_DEVICES_CONNECTED']=int(i/9)
        return results
    except Exception as err:
        _log.debug('Exception in getting information about serial devices from the RTAC: '+str(err))
        return results

def HTTP_unsecured_Check(**kwargs):
    """
    This is a function to check whether the HTTP server on a device is secured with a username and a password.
    """
    try:
        # Get the inputs needed
        IP=kwargs['TARGET_IPADDR']
        creds=['','']
        for key in kwargs.keys():
                if key=='DEFAULT_CREDS':
                        creds=kwargs['DEFAULT_CREDS']
        # Initialize the results dictionary
        results={}
        results['TARGET_IPADDR']=IP
        results['SCAN_NAME']='SAGE_HTTP_default_credential_Check'
        results['HTTP_UNSECURED']='N'
        
        # Get the information from the appropriate page and parse it.
        url = 'http://'+IP+'/'
        r = requests.get(url,verify=False)
        resp=str(r.content)
        status=r.status_code
        
        if status==200 and resp.find('password')<0:
            results['HTTP_UNSECURED']='Y'
        return results
    except Exception as err:
        _log.debug('Exception in authenticating to the SEL relay\'s web page: '+str(err))
        results['HTTP_UNSECURED']='Unknown'
        return results

def SAGE_HTTP_default_credential_Check(**kwargs):
    """
    This is a function to check the default credentials to login into the HTTP server on a SAGE RTU.
    """
    try:
        # Get the inputs needed
        IP=kwargs['TARGET_IPADDR']
        creds=['','']
        for key in kwargs.keys():
                if key=='DEFAULT_CREDS':
                        creds=kwargs['DEFAULT_CREDS']
        # Initialize the results dictionary
        results={}
        results['TARGET_IPADDR']=IP
        results['SCAN_NAME']='SAGE_HTTP_default_credential_Check'
        results['HTTP_DEFAULT_CREDS']='N'
        
        # Get the information from the appropriate page and parse it.
        url = 'http://'+IP+'/fs/login.htm'
        r = requests.post(url,verify=False,data={'uname':creds[0],'pword':creds[1]},allow_redirects=False)
        resp=r.content
        status=r.status_code
        # The SAGE sends a redirect with a message to indicate whether the login was successful.
        if status==302 and resp.find(b'User allowed')>=0:
            results['HTTP_DEFAULT_CREDS']='Y'
        return results
    except Exception as err:
        _log.debug('Exception in authenticating to the SEL relay\'s web page: '+str(err))
        results['HTTP_DEFAULT_CREDS']='Unknown'
        return results

def HTTP_default_credential_Check(**kwargs):
    """
    This is a function to check the default credentials to login into the HTTP server on any relay.
    """
    try:
        
        # Initialize the results dictionary
        results={}
        IP=kwargs['TARGET_IPADDR']
        results['TARGET_IPADDR']=IP
        results['TARGET_PORT']=kwargs['TARGET_PORT']
        results['SCAN_NAME']='HTTP_default_credential_Check'
        results['HTTP_DEFAULT_CREDS']='N'
        results['HTTP_UNSECURED']='N'
        # Step 1: We check if an HTTP server is secured or unsecured
        res=HTTP_unsecured_Check(**kwargs)
        
        if res['HTTP_UNSECURED']=='Y':
            results['HTTP_UNSECURED']='Y'
        else:
            r={}
            # Check if kwargs has a vendor specified, if so skip the scrape HTTP server step
            if kwargs.get('VENDOR')==None:
                # Scrape the HTTP server's home page to identify vendor
                r=scrape_http_server(**kwargs)
            else:
                r['VENDOR']=kwargs['VENDOR'].lower()
            # Call an appropriate function based on the vendor
            if r['VENDOR']=='schneider':
                results['HTTP_DEFAULT_CREDS']=SAGE_HTTP_default_credential_Check(**kwargs)['HTTP_DEFAULT_CREDS']
            elif r['VENDOR']=='sel':
                results['HTTP_DEFAULT_CREDS']=SEL_HTTP_default_credential_Check(**kwargs)['HTTP_DEFAULT_CREDS']
            else:
                _log.debug('No known HTTP credential scans available for this vendor device.')
                results['HTTP_DEFAULT_CREDS']='Unknown'      
        return results
    except Exception as err:
        _log.debug('Exception in performing the HTTP default credential check scan: '+str(err))
        results['HTTP_DEFAULT_CREDS']='Unknown'
        return results

def ROC_get_DeviceInfo(**kwargs):
    """
    This function pulls the relevant device information and returns a dictionary.
    """
    deviceIP=kwargs['TARGET_IPADDR']
    results={}
    results['TARGET_IPADDR']=deviceIP
    results['SCAN_NAME']='ROC_get_DeviceInfo'
    results['VENDOR']='Unknown'
    results['MODEL']='xxxxx'
    results['FIRMWARE_ID']='xxxxx'
    results['PART_NO']='xxxxx'
    results['DEVICE_NAME']='Unnamed'

    # We have the Model Dictionary from the manuals
    Model_Dict={1:'ROCPAC ROC300-Series',2:'FloBoss 407',3:'FlashPAC ROC300-Series',4:'FloBoss 107/503/1xx or RegFlo version 1.xx',5:'FloBoss 504',6:'ROC800 (809/827)',9:'3095FC',11:'DL8000'}

    try:
        # Build the ROC plus packet to get device information
        SrcUnit=b'\x03'
        SrcGroup=b'\x01'

        # First, we identify the device address if we don't know it already
        try:
            DestUnit=kwargs['ROC_ADDRESS']
            DestGroup=kwargs['ROC_GROUP']
            [DestUnit,DestGroup,Model]=ROC_get_DeviceAddress(deviceIP,group=DestGroup,unit=DestUnit)
        except KeyError:
            [DestUnit,DestGroup,Model]=ROC_get_DeviceAddress(deviceIP)
        # Populate the Model information & vendor information
        results['VENDOR']='Emerson Process Mgmt'
        results['MODEL']=Model_Dict[Model]
        
        # We appropriately build our next packet to request system variables based on the device
        # Some devices such as the FloBoss support only the ROC protocol, whereas other devices such as
        # the ROC 800 support the ROC plus protocol

        #Opcode 180 is to read parameters
        OpCode=b'\xb4'
        
        Payload=DestUnit+DestGroup+SrcUnit+SrcGroup+OpCode
        # Note: The index of the parameter corresponding to the firmware id varies based on the ROC plus version supported
        # If an incorrect index was used, we would get an error response code from the ROC
        if Model==6:
            parameterNames=['DEVICE_NAME','PART_NO','VENDOR','FIRMWARE_ID']
            paramAddresses=[b'\x02',b'\x03',b'\x05',b'\x25']
            ptType=b'\x5b'
        else:
            parameterNames=['DEVICE_NAME','PART_NO','VENDOR','FIRMWARE_ID']
            paramAddresses=[b'\x02',b'\x0b',b'\x0c',b'\x0b']
            ptType=b'\x0f'

        ptAddress=b'\x00'
        # We build our Payload for the Read parameters
        DataPayload=b''
        for paramAdd in paramAddresses:
            DataPayload+=ptType+ptAddress+paramAdd
        DataLength=bytes([len(DataPayload)+1])
        numParameters=bytes([len(paramAddresses)])
        Payload+=DataLength+numParameters+DataPayload

        #Payload=b"\x02\x02\x03\x01\x06\x00"
        
        CRC=CrcArc.calc(Payload)
        #print(CRC.to_bytes(2, byteorder='little'))
        Payload+=CRC.to_bytes(2, byteorder='little')
        
        # Once we build the packet, we send it and get the required response
        socket.setdefaulttimeout(5)
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            # ROC plus runs on port 4000
            ip_port=(deviceIP,4000) 
            s.connect(ip_port)
            s.sendall(Payload)
            try:
                data=s.recv(1024)
            except socket.timeout:
                return results
            if len(data)>0:
                s.close()
                respLength=data[5]
                # We need to make sure that the parameters we have requested are valid
                # We check to see if we have received an exception code
                if data[4]==0xff:
                    # This means that we have an error code
                    _log.debug("Received an exception code:"+str(data[5:6+respLength]))
                    print("Received an exception code:"+str(data[5:6+respLength]))
                else:
                    # We have received valid data, now we need to parse it accordingly
                    paramReturned=data[6]
                    length=len(data)-2
                    # We choose the system variable type according to ROC/ROC plus
                    if Model==6:
                        paramSearchStr=b'\x5b\x00'
                    else:
                        paramSearchStr=b'\x0f\x00'
                    # Cut the variables into chunks and then format them
                    respChunks=[]
                    respChunks=data[7:length].split(paramSearchStr)
                    respChunks=respChunks[1:]
                    i=0
                    for resp in respChunks:
                        value=resp[1:].decode()
                        value=value.replace(' ','')
                        value=value.replace('\x00','')
                        results[parameterNames[i]]=value
                        i+=1
        
        return results        
    except Exception as err:
        _log.debug('Exception when trying to read parameters over the ROC/ROC plus protocol:'+str(err))
        print('Exception when trying to read parameters over the ROC/ROC plus protocol:'+str(err))
        return results

def ROC_get_DeviceAddress(IP,group=0,unit=0):
    """
    This function attempts to discover the device's unit address and group address over the ROC and ROC plus protocols.
    """
    deviceIP=IP
    
    try:
        # ROC/ROC plus runs on port 4000
        ip_port=(deviceIP,4000) 
        
        # This is our ID and can be chosen at random
        SrcUnit=b'\x03'
        SrcGroup=b'\x01'
        # If we get passed an address we skip the search and get the model info directly by starting at the right values
        if group==0:
            GrpStart=2
        else:
            GrpStart=group
        if unit==0:
            UnitStart=1
        else:
            UnitStart=unit
        # We send a packet to get basic device information using Opcode 6
        OpCode=b'\x06'

        # We iterate over the address space until we get a response
        found_address=0
        model=0
        for dstGrp in range(GrpStart,255):
            DestGroup=dstGrp.to_bytes(1,byteorder='big')
            for dstUnit in range(UnitStart,255):
                DestUnit=dstUnit.to_bytes(1,byteorder='big')
                # Prepare the test payload
                Payload=DestUnit+DestGroup+SrcUnit+SrcGroup+OpCode+b'\x00'
                CRC=CrcArc.calc(Payload)
                Payload+=CRC.to_bytes(2, byteorder='little')
                socket.setdefaulttimeout(5)
                with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
                    s.connect(ip_port)
                    s.sendall(Payload)
                    try:
                        data=s.recv(1024)
                    except socket.timeout:
                        continue
                    if len(data)>0:
                        s.close()
                        model=data[24]
                        found_address=1
                        break
            if found_address==1:
                break
        _log.debug('IP address:'+IP+'ROC Unit address is:'+str(DestUnit)+ ',ROC Unit group is:'+str(DestGroup))
        return [DestUnit,DestGroup,model]   
    except Exception as err:
        _log.debug('Something went wrong!'+str(err))
        return [0,0,0]

def telnet_grab_banner(**kwargs):
    ip_address = kwargs['TARGET_IPADDR']
    port = kwargs['TARGET_PORT']

    sig_list = telnet_sigs
    expect_list = []

    for sig in sig_list:
        expect_list += sig['sigs']

    resp = None
    results = dict.fromkeys(['TARGET_IPADDR', 'SCAN_NAME', 'VENDOR', 'MODEL', 'SCAN_RESULT', 'SCAN_RESULT_DESC'])
    results['TARGET_IPADDR'] = kwargs['TARGET_IPADDR']
    results['SCAN_NAME'] = 'telnet_grab_banner'

    try: 
        with telnetlib.Telnet(ip_address, port) as tn:
            resp = tn.expect(expect_list, timeout=5)
    except Exception as err:
        results['SCAN_RESULTS'] = -1
        results['SCAN_RESULTS_DESC'] = 'Error connecting to telnet on {} port {}'.format(ip_address, port)
        _log.error("Telnet error: " + str(err))
    

    telnet_banner_found = False
    if resp != None:
        for sig in sig_list:
            if resp[2] in sig['sigs']:
                telnet_banner_found = True
                results['SCAN_RESULT'] = 1
                results['SCAN_RESULT_DESC'] = 'Success'
                results['VENDOR'] = sig['VENDOR']
                results['MODEL'] = sig['MODEL']

        #if resp[2] == telnet_sigs['Lantronix SLC32']:
        #    results['VENDOR'] = 'Lantronix'
        #    results['MODEL'] = 'SLC03212N-03'
        #elif resp[2] == telnet_sigs['SEL Relays']:
        #    results['VENDOR'] = 'SEL'

    if telnet_banner_found == False:
        results['SCAN_RESULT'] = 0
        results['SCAN_RESULT_DESC'] = 'No telnet banner was received or recognized'

    return results


def Lantronix_get_DeviceInfo(**kwargs):
    """
    This function pulls the relevant device information and returns a dictionary.
    """
    IP=kwargs['TARGET_IPADDR']

    tn=telnetlib.Telnet(IP)

    firstoutput=tn.read_until(b"login: ")

    # Initializing results
    results={}
    deviceIP=kwargs['TARGET_IPADDR']
    results['SCAN_NAME']='Lantronix_get_device_info'
    results['TARGET_IPADDR']=deviceIP
    results['MODEL']='Unknown'
    results['S/N'] = 'xxxxxxxx'
    results['DEVICE_NAME'] = 'None'
    results['FIRMWARE_VERSION']='None'
    results['SERIAL_DEVICES']='None'

    device_list_results={}
    device_list_results['DEVICE_PORT']='None'
    device_list_results['SUBDEVICE_NAME']='None'
    device_list_results['BAUD_RATE']='None'
    device_list_results['BANNER']='None'
    device_list_results['TELNET_ENABLED']='None'
    device_list_results['TELNET_PORT']='None'
    device_list_results['SSH_ENABLED']='None'
    device_list_results['SSH_PORT']='None'
    device_list_results['TCP_ENABLED']='None'
    device_list_results['TCP_PORT']='None'
    device_list_results['SUBDEVICE_IP_ADDRESS']='None'



    #enter username
    tn.write(b'sysadmin\r\n')

    #enter password
    secondoutput=tn.read_until(b"Password: ")

    #Help menu from SEL Device, not available on all devices
    tn.write(b'PASS\r\n')

    #Get the device name
    thirdoutput=tn.read_until(b"slc")
    forthoutput=tn.read_until(b">")
    results['DEVICE_NAME'] = 'slc'+str(forthoutput)[2:6]

    #Get info
    tn.write(b'show sysconfig\r\n')
    #Read all information until the next command line
    output=tn.read_until(b"[slc").decode('ascii')

    tn.write(b'logout\r\n')
    # Parse the output results

    try:
        # Now, we can parse the config file to populate the fields
        # Note: If there are multiple processors, this script will capture the details of only the first processor assuming it as the main processor.
        search_strings=[('Firmware Version:','S/N','FIRMWARE_VERSION'),('S/N: ','\r\n','S/N'), ('Model:','Power Supply','MODEL')]
        #serial_search_strings=[('Device Port:', 'Name:', 'DEVICE_PORT'),('Name:','\r\n','SUBDEVICE_NAME'),('Baud Rate:', 'Banner', 'BAUD_RATE'),('Banner:','\r\n','BANNER'),'Telnet:','\r\n','TELNET_ENABLED'),('Telnet Port:','\r\n','TELNET_PORT'),('SSH:','\r\n','SSH_ENABLED'),('SSH Port:','\r\n','SSH_PORT'),('TCP:','\r\n','TCP_ENABLED'),('TCP Port:','\r\n','TCP_PORT'),('  IP Address:','\r\n','SUBDEVICE_IP_ADDRESS')]
        serial_search_strings=[('Device Port:', 'Name:', 'DEVICE_PORT'),('Name:','\r\n','SUBDEVICE_NAME'),('Baud Rate:', 'Banner', 'BAUD_RATE'),('Banner:','\r\n','BANNER'),('Telnet:','\r\n','TELNET_ENABLED'),('Telnet Port:','\r\n','TELNET_PORT'),('SSH:','\r\n','SSH_ENABLED'),('SSH Port:','\r\n','SSH_PORT'),('TCP:','\r\n','TCP_ENABLED'),('TCP Port:','\r\n','TCP_PORT'),('  IP Address:','\r\n','SUBDEVICE_IP_ADDRESS')]

        maininfo,devicelist=output.split('Device Port Global Settings',1)

        for start,end,field in search_strings:
            split_resp=output.split(str(start))
            results[field]=split_resp[1].split(end)[0].strip()
        count = 0
        split_devicelist=[]

        split_devicelist=devicelist.split('\r\n\r\n')
        del split_devicelist[0]

        port_info={}
        portlength=0

        #following while loop iterates through all the device port listings
        #flexible as to how many there are
        while (portlength==0):
            if 'Device Port' in split_devicelist[count]:
                for start1,end1,field1 in serial_search_strings:
                    split_resp=split_devicelist[count].split(str(start1))
                    device_list_results[field1]=split_resp[1].split(end1)[0].strip()
                comstring="COM"+device_list_results['DEVICE_PORT']
                port_info[comstring]=device_list_results.copy()
                count=count+1
            else:
                portlength=1
        results['SERIAL_DEVICES']=port_info
        return results

    except Exception as err:
        _log.debug('Exception in getting the Lantronix device info: '+str(err))
    return results


def RTAC_get_database_name(IP,creds):
    """
    This is a function to login into the default postgres database on the RTAC,
    and find the appropriate database to pull configuration information.
    """
    try:
        dbname='postgres'
        conn_param="dbname='"+dbname+"' user='"+creds[0]+"' host='"+IP+"' password='"+creds[1]+"'"
        conn = psycopg2.connect(conn_param)
    except Exception as err:
        _log.debug("Unable to connect to the database:"+str(err))
        print("Unable to connect to the database:"+str(err))
        return ''
    try:
        cur=conn.cursor()
        cur.execute("""SELECT datname from pg_database""")
        # The relevant database that we want is one with the device model info.
        # Usually it is 4 digits
        for row in cur.fetchall():
            search_results=re.findall(re.compile('[\d]{4}'),row[0])
            if search_results!=[]:
                dbname=search_results[0]
                break
    except Exception as err:
        _log.debug("Error pulling info on the databases available:"+str(err))
        #print("Error pulling info on the databases available:"+str(err))
        return ''
    cur.close()
    conn.close()    
    return dbname
    
    
def RTAC_get_db_device_info(**kwargs):
    """
    This is a function to login into the appropriate device database on the RTAC,
    and pull configuration information.
    """
    # Take the relevant inputs
    IP=kwargs['TARGET_IPADDR']
    creds=kwargs['DEFAULT_CREDS']
    
    # Initialize the results dictionary
    results={}
    results['TARGET_IPADDR']=IP
    results['SCAN_NAME']='RTAC_get_db_device_info'
    results['HOST_NAME']='None'
    results['DEVICE_LOCATION']='None'
    results['MODEL'] = 'None'
    results['DEVICE_NAME'] = 'None'
    results['FIRMWARE_ID'] = 'Rxxx'
    results['SERIAL_DEVICES']={}
    results['NUM_SERIAL_DEVICES_CONNECTED']=0
    results['ETHERNET_DEVICES']={}
    results['NUM_ETHERNET_DEVICES_CONNECTED']=0
    
    # Identify and call the right database
    dbname=RTAC_get_database_name(IP,creds)
    if dbname=='':
        results['SCAN_RESULT']=-1
        results['SCAN_RESULT_DESC']='Error connecting to the maintenance database!'
        return results

    conn_param="dbname='"+dbname+"' user='"+creds[0]+"' host='"+IP+"' password='"+creds[1]+"'"
    conn = psycopg2.connect(conn_param)
    # Pass the database name to pull config information
    try:
        cur=conn.cursor()
        cur.execute("""SELECT * from public.get_fid_string()""")
        for row in cur.fetchall():
            #print(str(row))
            results['FIRMWARE_ID'] = row[0]
            results['MODEL'] = results['FIRMWARE_ID'].split('-R')[0]
        cur.execute("""SELECT * from public.get_device_info()""")
        for row in cur.fetchall():
            #print(str(row))
            results['HOST_NAME']=row[0]
            results['DEVICE_LOCATION']=row[7]
            results['DEVICE_NAME'] = row[8]
    except Exception as err:
        _log.debug("Error pulling config info from the database:"+str(err))
        #print("Error pulling config info from the database:"+str(err))
        cur.close()
        conn.close()
        results['SCAN_RESULT']=-1
        results['SCAN_RESULT_DESC']='Error pulling info from the database: '+str(err)
        return results
    else:
        try:
            # Pull information on serially connected devices from the database
            cur.execute("""SELECT * from schema_fw.list_serial_connected_ieds()""")
            device_count=0
            for row in cur.fetchall():
                #print(str(row))
                device_count+=1
                protocol=row[1]
                if protocol.find('SEL')>=0:
                    vendor='SEL'
                else:
                    vendor='Unknown'
                results['SERIAL_DEVICES']['COM'+str(row[2])]={'DEVICE_NAME':row[0],'SERIAL_PROTOCOL':protocol,'MODEL':'Unknown','VENDOR':vendor,'INTERFACE_TYPE':row[3],'BAUD_RATE':str(row[4]),'DATA_BITS':str(row[5]),'PARITY':row[6],'STOP_BITS':str(row[7])}
            results['NUM_SERIAL_DEVICES_CONNECTED']=device_count

            # Pull information on ethernet connected devices from the database
            cur.execute("""SELECT * from schema_fw.list_ethernet_connected_ieds()""")
            device_count=0
            for row in cur.fetchall():
                #print(str(row))
                device_count+=1
                protocol=row[2]
                if protocol.find('SEL')>=0:
                    vendor='SEL'
                else:
                    vendor='Unknown'
                results['ETHERNET_DEVICES']['CONN:'+str(device_count)]={'DEVICE_NAME':row[1],'PROTOCOL':protocol,'MODEL':'Unknown','VENDOR':vendor,'INTERFACE_TYPE':row[3],'PORT':str(row[4]),'DEVICE_IPADDR':row[5]}
            results['NUM_ETHERNET_DEVICES_CONNECTED']=device_count
            
        except Exception as err:
            _log.debug("Error pulling info on connected devices from the database:"+str(err))
            #print("Error pulling info on connected devices from the database:"+str(err))
            cur.close()
            conn.close()
            results['SCAN_RESULT']=-1
            results['SCAN_RESULT_DESC']='Error pulling info on connected devices from the database:'+str(err)
            return results
        # If all goes well, close the database connection
        cur.close()
        conn.close()
    results['SCAN_RESULT']=1
    results['SCAN_RESULT_DESC']='Scan completed successfully!'
    return results


