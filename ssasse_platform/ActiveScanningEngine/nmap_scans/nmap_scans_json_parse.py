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
import json
import logging
_log = logging.getLogger(__name__)

def nmap_json_parse(IP,data,name=''):
    """
    Function to parse and return results to the inference engine.
    """
    try:
        new_results={}
        new_results['TARGET_IPADDR'] = IP
        new_results['SCAN_NAME'] = name
        if data['nmap']['scaninfo'].get('error') is not None:
            # We can know why the scan failed and dump that info into the results
            new_results['SCAN_RESULT']=0
            new_results['SCAN_RESULT_DESC']='Error with scan:'+str(data['scaninfo']['error'])
            print('Error performing an nmap scan!')
            _log.debug('Error performing an nmap scan!')
            return new_results
        elif not bool(data['scan']):
            # Check if we have empty results from the nmap scan
            # If so, we need to indicate this in the error code and description
            new_results['SCAN_RESULT']=0
            new_results['SCAN_RESULT_DESC']='Empty dictionary returned by nmap scans!'
            print('Empty dictionary returned by nmap scans!')
            _log.debug('Empty dictionary returned by nmap scans!')
            return new_results
        else:
            # We have valid results and need to format it properly
            
            if name=='nmap_service_scan':
                new_results['TARGET_PORTS'] = []
                # Then, we collect the information on open ports
                for key in data['scan'][IP].keys():
                    if key=='tcp' or key == 'udp':
                        ports_dict=data['scan'][IP][key]
                        new_results['PORTS']={}
                        # We create a dictionary for each of the ports scanned
                        for key,value in ports_dict.items():
                            new_results['PORTS'][key]={}
                            new_results['TARGET_PORTS'].append(key)
                            for k,v in value.items():
                                if k=='state':
                                    new_results['PORTS'][key]['PORT_STATE']=v
                                elif k=='name':
                                    new_results['PORTS'][key]['SERVICE_NAME']=v
                                elif k=='product':
                                    new_results['PORTS'][key]['SERVICE_VENDOR']=v
                                elif k=='version':
                                    new_results['PORTS'][key]['SERVICE_VERSION']=v
                                elif k=='state':
                                    new_results['DEVICE_STATUS']=v
                                elif k=='script':
                                    for a,b in v.items():
                                        new_results['PORTS'][key][a.upper()]=b
            elif name == 'nmap_TCP_UDP_ping_scan' or name == 'nmap_arp_ping_scan':
                new_results['DISCOVERED_TARGETS']={}
                # Each IP discovered has a dictionary of attributes inside the scan results field
                for target,value in data['scan'].items():
                    new_results['DISCOVERED_TARGETS'][target]={}
                    new_results['DISCOVERED_TARGETS'][target]['TARGET_MACADDR']=value['addresses'].get('mac','')
                    new_results['DISCOVERED_TARGETS'][target]['TARGET_STATE']=value['status']['state']
                    new_results['DISCOVERED_TARGETS'][target]['TARGET_DETECTION']=value['status']['reason']
            else:
                new_results['NMAP_RESULTS']=data['scan']
                    
            new_results['SCAN_RESULT']=1
            new_results['SCAN_RESULT_DESC']='Scan executed successfully!'
            #print(str(new_results)+'\n')
            return new_results
    except Exception as e:
        print('Problem with parsing nmap scan results!')
        _log.exception('Problem with parsing nmap scan results!')
        new_results['SCAN_RESULT']=-1
        new_results['SCAN_RESULT_DESC']='Problem with parsing nmap scan results:'+str(e)
        return new_results

if __name__=='__main__':
    
    IP_list=['192.168.8.85','192.168.8.84','172.17.0.19','172.17.0.19','172.17.0.19','172.17.0.19','172.17.0.19','172.17.0.19','172.17.0.19','172.17.0.19','172.17.0.19','172.17.0.19','172.17.0.19']
    
    #function_list=['nmap_enip_enumerate_scan','nmap_bacnet_discover_enumerate_scan','nmap_s7_enumerate_scan','nmap_codesys_v2_discover_scan','nmap_fox_info_scan','nmap_modicon_info_scan','nmap_omron_tcp_scan','nmap_omron_udp_scan','nmap_pcworx_info_scan','nmap_proconos_info_scan','nmap_custom_scan','nmap_arp_ping_scan','nmap_banner_grab_scan','nmap_service_scan']
    function_list=['nmap_TCP_UDP_ping_scan']
    path='C:/Users/asho708/OneDrive - PNNL/Desktop/Shared_folder/Nmap_results/'
    port=['44818']
    
    try:
##        for i in range(len(function_list)):
##            filename=path+function_list[i]+".json"
##            print(function_list[i]+'\n')
##            with open(filename,'r') as read_file:
##                results=json.load(read_file)
##                IP=IP_list[i]
##                nmap_json_parse(IP,results)
        filename=path+function_list[0]+".json"
        with open(filename,'r') as read_file:
            results=json.load(read_file)
        nmap_json_parse('172.17.0.0/28',results,'nmap_TCP_UDP_ping_scan')                
    except Exception as e:
        print('Problem!')
        _log.exception('Problem parsing json files!')
        pass
