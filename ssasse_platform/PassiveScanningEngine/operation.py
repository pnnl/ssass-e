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

import datetime

class Operation:
    def __init__(self,
                ts="",  
                source_ip="",
                destination_ip="",
                dnp3_master_id="",
                dnp3_slave_id="",
                modbus_slave_id="",
                dnp3_port="",
                modbus_port="",
                fc="",
                fn="",
                is_orig=False,
                source_port="",
                destination_port="",
                source_macaddress="",
                dest_macaddress="",
                hostname="",
                protocol="",
                master_slave=False
                ):
        self.ts = ts
        self.source_ip = source_ip 
        self.destination_ip = destination_ip 
        self.fc = fc 
        self.fn = fn 
        self.is_orig = is_orig
        self.source_port = source_port
        self.destination_port = destination_port
        self.source_macaddress = source_macaddress
        self.dest_macaddress = dest_macaddress
        self.hostname = hostname
        self.protocol = protocol
        self.is_master_slave = master_slave
        self.dnp3_master_id = dnp3_master_id
        self.dnp3_slave_id = dnp3_slave_id,
        self.modbus_slave_id = modbus_slave_id
        self.dnp3_port=dnp3_port,
        self.modbus_port=modbus_port
        self.ctr = 0

    def getDict(self):
        rst = {"TIMESTAMPED": self.ts,
               "TARGET_IPADDR": self.source_ip,
               "DEST_IPADDR": self.destination_ip,
               "DNP3_MASTER_ID":self.dnp3_master_id,
               "DNP3_SLAVE_ID":self.dnp3_slave_id,
               "MODBUS_SLAVE_ID":self.modbus_slave_id,
               "DNP3_PORT":self.dnp3_port,
               "MODBUS_PORT":self.modbus_port,
               "PROTOCOL_FUNCTION_CODE": self.fc,
               "PROTOCOL_FUNCTION_CODE_DESC": self.fn,
               "IS_ORIGINATOR": self.is_orig,
               "SOURCE_PORT": self.source_port,
               "DEST_PORT": self.destination_port,
               "TARGET_MACADDR": self.source_macaddress,
               "DEST_MACADDR": self.dest_macaddress,
               "HOSTNAME": self.hostname,
               "PROTOCOL": self.protocol,
               "SUPPORTS_MASTER_AND_SLAVE": self.is_master_slave,
               "CTR": self.ctr}
        return rst

    def __str__(self):
        return '''
    TIMESTAMPED = {0} 
    TARGET_IPADDR = {1} 
    DEST_IPADDR = {2} 
    DNP3_MASTER_ID = {3}
    DNP3_SLAVE_ID = {4}
    MODBUS_SLAVE_ID = {5}
    DNP3_PORT = {6}
    MODBUS_PORT = {7}
    PROTOCOL_FUNCTION_CODE = {8}
    PROTOCOL_FUNCTION_CODE_DESC = {9}
    IS_ORIGINATOR = {10}
    SOURCE_PORT = {11}
    DEST_PORT = {12}
    TARGET_MACADDR = {13}
    DEST_MACADDR = {14}
    HOSTNAME = {15}
    PROTOCOL = {16}
    SUPPORTS_MASTER_AND_SLAVE = {17}
'''.format(
            self.ts.__str__(),
#            datetime.datetime.fromtimestamp(self.ts),
            self.source_ip,
            self.destination_ip,
            self.dnp3_master_id,
            self.dnp3_slave_id,
            self.modbus_slave_id,
            self.dnp3_port,
            self.modbus_port,
            self.fc,
            self.fn,
            self.is_orig,
            self.source_port,
            self.destination_port,
            self.source_macaddress,
            self.dest_macaddress,
            self.hostname,
            self.protocol,
            self.is_master_slave
            ) 

