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

#!/usr/bin/python3
"""

Module implementing functions for different types of nmap scans.

Nmap scanning is supported using python-nmap.


"""
import sys
import logging
import re
_log=logging.getLogger(__name__)

import json
from .nmap_scans_json_parse import nmap_json_parse

try:
    import nmap
except ImportError:
    print("Please install python-nmap to run nmap scans from Python.")

def nmap_enip_enumerate_scan(**kwargs):
    """
    Function to send ENIP broadcast packets and identify devices that support it on the network.
    """
    IP=kwargs['TARGET_IPADDR']
    scan_args="--script enip-enumerate"
    port='44818'
    try:
        nm = nmap.PortScanner()
        # Scan command uses subprocess to call nmap and finally returns the result in a dictionary
        results=nm.scan(hosts=IP, ports=port, arguments=scan_args, sudo=True)
        
        #print(results)
        # We need to format this to match our dictionary keys and return it
        return nmap_json_parse(IP,results,name='nmap_enip_enumerate_scan')
       
    except Exception as e:
        print("Error occured when attempting to run nmap scan! ",e)
        _log.exception('Error occured when attempting to run nmap scan! ')
        new_results={}
        new_results['SCAN_RESULT']=-1
        new_results['SCAN_RESULT_DESC']='Error performing an nmap scan:'+str(e)


def nmap_bacnet_discover_enumerate_scan(**kwargs):
    """
    Function to discover and enumerate BACnet devices on the network.
    """

    scan_results = dict.fromkeys(['TARGET_IPADDR', 'SCAN_NAME', 'MODEL', 'VENDOR', 'BACNET_VENDOR', 'FIRMWARE_ID', 'SCAN_RESULT', 'SCAN_RESULT_DESC'])

    scan_results['TARGET_IPADDR'] = kwargs['TARGET_IPADDR']
    scan_results['SCAN_NAME'] = 'nmap_bacnet_discover_enumerate'

    IP=kwargs['TARGET_IPADDR']
    scan_args="-sU --script bacnet-info"
    port='47808'
    try:
        nm = nmap.PortScanner()
        # Scan command uses subprocess to call nmap and finally returns the result in a dictionary
        results=nm.scan(hosts=IP, ports=port, arguments=scan_args, sudo=True)
        if not bool(results['scan']):
            scan_results['SCAN_RESULT'] = -1
            scan_results['SCAN_RESULT_DESC'] = 'nmap scan of {} failed'.format(IP)
            return scan_results
        else:
            scan_results['SCAN_RESULT'] = 1
            scan_results['SCAN_RESULT_DESC'] = 'Success'
            bacnet_script_results = results['scan'][IP]['udp'][int('47808')]['script']['bacnet-info'].strip().replace(' ','')
            
            m = re.search('VendorID:(.+?)\(([0-9]+)\)', bacnet_script_results)
            if m:
                scan_results['BACNET_VENDOR'] = m.group(2)
            m = re.search('Firmware:(.+?)\\n', bacnet_script_results)
            if m:
                scan_results['FIRMWARE_ID'] = m.group(1)
            m = re.search('ModelName:(.+?)\\n', bacnet_script_results)
            if m:
                scan_results['MODEL'] = m.group(1)
            m = re.search('VendorName:(.+?)\\n', bacnet_script_results)
            if m:
                scan_results['VENDOR'] = m.group(1)


            #print(bacnet_script_results)
        scan_results['SCAN_NAME']='nmap_bacnet_discover_enumerate_scan'
        
        #print(results)
        # We need to format this to match our dictionary keys and return it
        return scan_results
        #return nmap_json_parse(IP,results)
        
    except Exception as e:
        print("Error occured when attempting to run nmap scan! ",e)
        _log.exception('Error occured when attempting to run nmap scan! ')
        new_results={}
        new_results['SCAN_RESULT']=-1
        new_results['SCAN_RESULT_DESC']='Error performing an nmap scan:'+str(e)


def nmap_s7_enumerate_scan(**kwargs):
    """
    Function to discover and enumerate Siemens Step 7 devices on the network.
    """
    IP=kwargs['TARGET_IPADDR']
    scan_args="--script s7-enumerate -sV"
    port='102'
    try:
        nm = nmap.PortScanner()
        # Scan command uses subprocess to call nmap and finally returns the result in a dictionary
        results=nm.scan(hosts=IP, ports=port, arguments=scan_args, sudo=True)
        
        #print(results)
        # We need to format this to match our dictionary keys and return it
        return nmap_json_parse(IP,results,name='nmap_s7_enumerate_scan')
        
    except Exception as e:
        print("Error occured when attempting to run nmap scan!",e)
        _log.exception('Error occured when attempting to run nmap scan! ')
        new_results={}
        new_results['SCAN_RESULT']=-1
        new_results['SCAN_RESULT_DESC']='Error performing an nmap scan:'+str(e)


def nmap_codesys_v2_discover_scan(**kwargs):
    """
    Function to discover and enumerate devices that support codesys_v2 on the network.
    """
    IP=kwargs['TARGET_IPADDR']
    scan_args="--script codesys-v2-discover"
    port="1200,2455" 
    try:
        nm = nmap.PortScanner()
        # Scan command uses subprocess to call nmap and finally returns the result in a dictionary
        results=nm.scan(hosts=IP, ports=port, arguments=scan_args, sudo=True)
        
        #print(results)
        # We need to format this to match our dictionary keys and return it
        return nmap_json_parse(IP,results,name='nmap_codesys_v2_discover_scan')
        
    except Exception as e:
        print("Error occured when attempting to run nmap scan!",e)
        _log.exception('Error occured when attempting to run nmap scan! ')
        new_results={}
        new_results['SCAN_RESULT']=-1
        new_results['SCAN_RESULT_DESC']='Error performing an nmap scan:'+str(e)


def nmap_fox_info_scan(**kwargs):
    """
    Function to discover and enumerate devices that support the Niagara Fox protocol on the network.
    """
    IP=kwargs['TARGET_IPADDR']
    scan_args="--script fox-info"
    port="1911" 
    try:
        nm = nmap.PortScanner()
        # Scan command uses subprocess to call nmap and finally returns the result in a dictionary
        results=nm.scan(hosts=IP, ports=port, arguments=scan_args, sudo=True)
        
        #print(results)
        # We need to format this to match our dictionary keys and return it
        return nmap_json_parse(IP,results,name='nmap_fox_info_scan')
        
    except Exception as e:
        print("Error occured when attempting to run nmap scan!",e)
        _log.exception('Error occured when attempting to run nmap scan! ')
        new_results={}
        new_results['SCAN_RESULT']=-1
        new_results['SCAN_RESULT_DESC']='Error performing an nmap scan:'+str(e)


def nmap_modicon_info_scan(**kwargs):
    """
    Function to discover and enumerate devices that support the Modicon protocol on the network.
    """
    IP=kwargs['TARGET_IPADDR']
    scan_args="--script modicon-info -sV"
    port="502" 
    try:
        nm = nmap.PortScanner()
        # Scan command uses subprocess to call nmap and finally returns the result in a dictionary
        results=nm.scan(hosts=IP, ports=port, arguments=scan_args, sudo=True)
        
        #print(results)
        # We need to format this to match our dictionary keys and return it
        return nmap_json_parse(IP,results,name='nmap_modicon_info_scan')
    
    except Exception as e:
        print("Error occured when attempting to run nmap scan!",e)
        _log.exception('Error occured when attempting to run nmap scan! ')
        new_results={}
        new_results['SCAN_RESULT']=-1
        new_results['SCAN_RESULT_DESC']='Error performing an nmap scan:'+str(e)


def nmap_omron_tcp_scan(**kwargs):
    """
    Function to discover and enumerate devices that support omron_tcp on the network.
    """
    IP=kwargs['TARGET_IPADDR']
    scan_args="--script omrontcp-info"
    port="9600" 
    try:
        nm = nmap.PortScanner()
        # Scan command uses subprocess to call nmap and finally returns the result in a dictionary
        results=nm.scan(hosts=IP, ports=port, arguments=scan_args, sudo=True)
        
        #print(results)
        # We need to format this to match our dictionary keys and return it
        return nmap_json_parse(IP,results,name='nmap_omron_tcp_scan')
        
    except Exception as e:
        print("Error occured when attempting to run nmap scan!",e)
        _log.exception('Error occured when attempting to run nmap scan! ')
        new_results={}
        new_results['SCAN_RESULT']=-1
        new_results['SCAN_RESULT_DESC']='Error performing an nmap scan:'+str(e)


def nmap_omron_udp_scan(**kwargs):
    """
    Function to discover and enumerate devices that support omron_udp on the network.
    """
    IP=kwargs['TARGET_IPADDR']
    scan_args="--script omronudp-info -sU"
    port="9600" 
    try:
        nm = nmap.PortScanner()
        # Scan command uses subprocess to call nmap and finally returns the result in a dictionary
        results=nm.scan(hosts=IP, ports=port, arguments=scan_args, sudo=True)
        
        #print(results)
        # We need to format this to match our dictionary keys and return it
        return nmap_json_parse(IP,results,name='nmap_omron_udp_scan')
        
    except Exception as e:
        print("Error occured when attempting to run nmap scan!",e)
        _log.exception('Error occured when attempting to run nmap scan! ')
        new_results={}
        new_results['SCAN_RESULT']=-1
        new_results['SCAN_RESULT_DESC']='Error performing an nmap scan:'+str(e)


def nmap_pcworx_info_scan(**kwargs):
    """
    Function to discover and enumerate devices that support the PC worx protocol on the network.
    """
    IP=kwargs['TARGET_IPADDR']
    scan_args="--script pcworx-info"
    port="1962" 
    try:
        nm = nmap.PortScanner()
        # Scan command uses subprocess to call nmap and finally returns the result in a dictionary
        results=nm.scan(hosts=IP, ports=port, arguments=scan_args, sudo=True)
        
        #print(results)
        # We need to format this to match our dictionary keys and return it
        return nmap_json_parse(IP,results,name='nmap_pcworx_info_scan')
        
    except Exception as e:
        print("Error occured when attempting to run nmap scan!",e)
        _log.exception('Error occured when attempting to run nmap scan! ')
        new_results={}
        new_results['SCAN_RESULT']=-1
        new_results['SCAN_RESULT_DESC']='Error performing an nmap scan:'+str(e)


def nmap_proconos_info_scan(**kwargs):
    """
    Function to discover and enumerate devices that support the ProConOS/MultiProg protocol on the network.
    """
    IP=kwargs['TARGET_IPADDR']
    scan_args="--script proconos-info -sV"
    port="20547" 
    try:
        nm = nmap.PortScanner()
        # Scan command uses subprocess to call nmap and finally returns the result in a dictionary
        results=nm.scan(hosts=IP, ports=port, arguments=scan_args, sudo=True)
        
        #print(results)
        # We need to format this to match our dictionary keys and return it
        return nmap_json_parse(IP,results,name='nmap_proconos_info_scan')
        
    except Exception as e:
        print("Error occured when attempting to run nmap scan!",e)
        _log.exception('Error occured when attempting to run nmap scan! ')
        new_results={}
        new_results['SCAN_RESULT']=-1
        new_results['SCAN_RESULT_DESC']='Error performing an nmap scan:'+str(e)


def nmap_arp_ping_scan(**kwargs):
    """
    Function to perform an ARP ping nmap scan on the network.
    """
    IP=kwargs['TARGET_IPADDR']
    try:
        scan_args='-sn -PE'
        port=''
    except Exception as e:
        print("No arguments or port supplied for custom nmap scan! ",e)
        scan_args=''
        pass
     
    try:
        nm = nmap.PortScanner()
        # Scan command uses subprocess to call nmap and finally returns the result in a dictionary
        results=nm.scan(hosts=IP, arguments=scan_args, sudo=True)
        
        #print(results)
        # We need to format this to match our dictionary keys and return it
        return nmap_json_parse(IP,results,name='nmap_arp_ping_scan')
        
    except Exception as e:
        print("Error occured when attempting to run nmap scan!",e)
        _log.exception('Error occured when attempting to run nmap scan! ')
        new_results={}
        new_results['SCAN_RESULT']=-1
        new_results['SCAN_RESULT_DESC']='Error performing an nmap scan:'+str(e)


def nmap_banner_grab_scan(**kwargs):
    """
    Function to grab banners which connects to open TCP ports and prints out anything sent by the listening service within five seconds. The banner will be truncated to fit into a single line, but an extra line may be printed for every increase in the level of verbosity requested on the command line.
    """
    IP=kwargs['TARGET_IPADDR']
    try:
        scan_args="--script banner -sV"
        port=kwargs['NMAP_CUSTOM_SCAN_PORTS']
    
    except Exception as e:
        print("No arguments or port supplied for custom nmap scan! ",e)
        scan_args='--script banner'
        port='1-65535'
        pass
     
    try:
        nm = nmap.PortScanner()
        # Scan command uses subprocess to call nmap and finally returns the result in a dictionary
        results=nm.scan(hosts=IP, ports=port, arguments=scan_args, sudo=True)
        
        #print(results)
        # We need to format this to match our dictionary keys and return it
        return nmap_json_parse(IP,results,name='nmap_banner_grab_scan')
        
    except Exception as e:
        print("Error occured when attempting to run nmap scan!",e)
        _log.exception('Error occured when attempting to run nmap scan! ')
        new_results={}
        new_results['SCAN_RESULT']=-1
        new_results['SCAN_RESULT_DESC']='Error performing an nmap scan:'+str(e)


def nmap_custom_scan(**kwargs):
    """
    Function to perform custom nmap scans on the network.
    """
    IP=kwargs['TARGET_IPADDR']
    try:
        scan_args=kwargs['NMAP_CUSTOM_SCAN_ARGS']
        port=kwargs['TARGET_PORTS']
    except Exception as e:
        print("No arguments or port supplied for custom nmap scan! ",e)
        scan_args=''
        port=''
        pass
     
    try:
        nm = nmap.PortScanner()
        # Scan command uses subprocess to call nmap and finally returns the result in a dictionary
        results=nm.scan(hosts=IP, ports=port, arguments=scan_args, sudo=True)
        
        #print(results)
        # We need to format this to match our dictionary keys and return it
        return nmap_json_parse(IP,results,name='nmap_custom_scan')
        
    except Exception as e:
        print("Error occured when attempting to run nmap scan!",e)
        _log.exception('Error occured when attempting to run nmap scan! ')
        new_results={}
        new_results['SCAN_RESULT']=-1
        new_results['SCAN_RESULT_DESC']='Error performing an nmap scan:'+str(e)


def nmap_service_scan(**kwargs):
    """
    Function to perform port and service detection scans on the network.
    """
    IP=kwargs['TARGET_IPADDR']
    try:
        scan_args='-A -sV'
        port=kwargs['TARGET_PORTS']
    except Exception as e:
        print("No arguments or port supplied for custom nmap scan! ",e)
        scan_args='-A -sV'
        port='21-23'
        pass
     
    try:
        nm = nmap.PortScanner()
        # Scan command uses subprocess to call nmap and finally returns the result in a dictionary
        results=nm.scan(hosts=IP, ports=port, arguments=scan_args, sudo=True)
        
        name = 'nmap_service_scan'
        #print(results)
        # We need to format this to match our dictionary keys and return it
        return nmap_json_parse(IP,results,name=name)
        
    except Exception as e:
        print("Error occured when attempting to run nmap scan!",e)
        _log.exception('Error occured when attempting to run nmap scan! ')
        new_results={}
        new_results['SCAN_RESULT']=-1
        new_results['SCAN_RESULT_DESC']='Error performing an nmap scan:'+str(e)


def nmap_TCP_UDP_ping_scan(**kwargs):
    """
    Function to perform TCP SYN, ACK, and UDP ping scans on the network.
    """
    IP=kwargs['TARGET_IPADDR']
    try:
        tcp_port=kwargs['TARGET_PORTS']
        udp_port=tcp_port
    except Exception as e:
        print("No arguments or port supplied for custom nmap scan! ",e)
        scan_args=''
        tcp_port='21-23,69,80,102,123,443,502,2404,4000,4712,4713,5432,20000,47808'
        udp_port='69,123,502,1594,4000,20000,47808'
        pass
    # Build the scan arguments to perform all three scans on all the ports passed.
    # If no ports are passed, then the default ports on each of these scans will be used by nmap.
    scan_args='-sn -PS'+tcp_port+' -PA'+tcp_port+' -PU'+udp_port 
    try:
        nm = nmap.PortScanner()
        # Scan command uses subprocess to call nmap and finally returns the result in a dictionary
        results=nm.scan(hosts=IP, arguments=scan_args, sudo=True)
        
        #print(results)
        # We need to format this to match our dictionary keys and return it
        return nmap_json_parse(IP,results,name='nmap_TCP_UDP_ping_scan')
        
    except Exception as e:
        print("Error occured when attempting to run nmap scan!",e)
        _log.exception('Error occured when attempting to run nmap scan! ')
        new_results={}
        new_results['SCAN_RESULT']=-1
        new_results['SCAN_RESULT_DESC']='Error performing an nmap scan:'+str(e)
