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


class Packet(object):
    def __init__(self,
                ts="",  
                sender="",
                receiver="",
                protocol_type="",
                tcp_flag=-1,
                service="",
                packet_len="",
                conn="", **kwargs
                ):
        self.ts = ts
        self.sender = sender
        self.receiver = receiver
        self.protocol_type=protocol_type
        self.tcp_flag = tcp_flag
        self.service = service 
        self.packet_len = packet_len
        self.conn = conn

    def getDict(self):
        rst = {"TIMESTAMPED": self.ts,
               "TARGET_IPADDR": self.conn[0],
               "DEST_IPADDR": self.conn[2],
               "TCP": self.protocol_type,
               "PROTOCOL": self.service,
               "PACKET_LENGTH": self.packet_len,
               "SOURCE_PORT": self.conn[1],
               "DEST_PORT": self.conn[3]}
        return rst

    def __str__(self):
        return '''
    TIMESTAMPED = {0} 
    TARGET_IPADDR = {1} 
    DEST_IPADDR = {2} 
    TCP = {3}
    TCP_FLAGS = {4} 
    PROTOCOL = {5} 
    PACKET_LENGTH = {6} 
    SOURCE_PORT = {7}
    DEST_PORT = {8}
'''.format(
            datetime.datetime.fromtimestamp(self.ts),
            self.conn[0],
            self.conn[2],
            self.protocol_type,
            self.tcp_flag,
            self.service,
            self.packet_len,
            self.conn[1],
            self.conn[3]
            ) 


class TcpPacket(Packet):
    def __init__(self,
                ts="",
                sender="",
                receiver="",
                protocol_type="",
                tcp_flag=-1,
                service="",
                packet_len="",
                conn="", **kwargs
                ):
        super(TcpPacket, self).__init__(ts=ts, sender=sender, receiver=receiver, protocol_type=protocol_type,
                                        tcp_flag=tcp_flag, service=service, packet_len=packet_len, conn=conn, 
                                        **kwargs
                                       )
        self.seq = ""
        self.ack = ""
        self.payload = ''
        self.is_orig = 0

    def getDict(self):
        rst = super(TcpPacket, self).getDict()
        # string with the packets TCP flags
        # S: SYN, F: FIN, R: RST, A: ACK, P: PUSH
        rst['TCP_FLAGS'] = self.tcp_flag
        rst['SEQ'] = self.seq
        rst['ACK'] = self.ack
        rst['IS_ORIGINATOR'] = self.is_orig
#        rst['payload'] = self.payload

        return rst

    def __str__(self):
        return '''
    TIMESTAMPED = {0} 
    TARGET_IPADDR = {1} 
    DEST_IPADDR = {2} 
    TCP = {3}
    TCP_FLAGS = {4} 
    PROTOCOL = {5} 
    PACKET_LENGTH = {6} 
    SOURCE_PORT = {7}
    DEST_PORT = {8}
    SEQ = {9}
    ACK = {10}
    IS_ORIGINATOR = {11}
'''.format(
                datetime.datetime.fromtimestamp(self.ts),
                self.conn[0],
                self.conn[2],
                self.protocol_type,
                self.tcp_flag,
                self.service,
                self.packet_len,
                self.conn[1],
                self.conn[3],
                self.seq,
                self.ack,
                self.is_orig
            )

class ServicePacket(Packet):
    def __init__(self,
            ts="",
            sender="",
            receiver="",
            protocol_type="",
            tcp_flag=-1,
            service="",
            packet_len="",
            conn="", **kwargs
            ):
        super(ServicePacket, self).__init__(ts=ts, sender=sender, receiver=receiver, protocol_type=protocol_type,
                                        tcp_flag=tcp_flag, service=service, packet_len=packet_len, conn=conn, 
                                        **kwargs
                                        )
        self.is_orig = 0
        # method
        self.method = ''
        ## username
        self.username = ''
        ## password
        self.password = ''
        ## command line
        self.command_line = ''
        ## URI used in the request.
        self.uri = ''
        ## Value of the version portion of the request.
        self.version = ''
        ## Status code returned by the server.
        self.status_code = ''
        ## Status message returned by the server.
        self.status_msg = ''
   
    def getDict(self):
        #rst = super(ServicePacket, self).getDict()
        rst = {
                "TIMESTAMPED": self.ts,
                "TARGET_IPADDR": self.conn[0],
                "DEST_IPADDR": self.conn[2],
                "TCP": self.protocol_type,
                "PACKET_LENGTH": self.packet_len,
                "SOURCE_PORT": self.conn[1],
                "DEST_PORT": self.conn[3],
                "TARGET_MACADDR": self.source_macaddress,
                "DEST_MACADDR": self.dest_macaddress,
                "SERVICE": self.service,
                "USERNAME": self.username,
                "PASSWORD": self.password,
                "COMMAND_LINE": self.command_line,
                "URI": self.uri,
                "VERSION": self.version,
                "STATUS_CODE": self.status_code,
                "STATUS_MSG": self.status_msg,
                "IS_ORIGINATOR": self.is_orig,
                "METHOD": self.method,
                "CTR": "234"}
        return rst
 
