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

from .packet import Packet, TcpPacket, ServicePacket
import datetime

def parse_conn(conn, packet):
    # Connection tuple 
    conn_tuple = conn[0]
    orig_h = str(conn_tuple[0])
    orig_p = str(conn_tuple[1])
    resp_h = str(conn_tuple[2])
    resp_p = str(conn_tuple[3])
    packet.conn = (orig_h, orig_p, resp_h, resp_p)
    #print(packet.conn)

    # Service
    packet.service = list(map(str, conn[5]))
    #print(packet.service)

    # conn_id
    # conn_id = str(conn[7]) 
    #print(conn_id)

def parse_hdr(hdr, packet):
    # IPv4
    if hdr[0] is not None:
        #print("ip4:{}".format(hdr[0]))
        packet.packet_len = hdr[0][2].value
        packet.sender = str(hdr[0][6])
        packet.receiver = str(hdr[0][7])
        print("packet_len: {}, src: {}, dst: {}".format(packet.packet_len, packet.sender, packet.receiver))

    # IPv6
    elif hdr[1] is not None: 
        #print("ip6")
        packet.packet_len = hdr[1][2].value
        packet.sender = str(hdr[1][5])
        packet.receiver = str(hdr[1][6])
        print("packet_len: {}, src: {}, dst: {}".format(packet.packet_len, packet.sender, packet.receiver))

    # TCP
    if hdr[2] is not None:
        packet.protocol_type = "TCP"
        print(packet.protocol_type)
        packet.tcp_flag = hdr[2][6].value
        print("tcp_flag: {}".format(packet.tcp_flag))
        print("TCP....packet_len: {}, src: {}, dst: {}".format(packet.packet_len, packet.sender, packet.receiver))

    # UDP
    elif hdr[3] is not None:
        packet.protocol_type = "UDP"
        #print(packet.protocol_type)

    # ICMP
    elif hdr[4] is not None:
        packet.protocol_type = "ICMP"
        #print(packet.protocol_type)
 
def parse_sender_receiver(conn, is_orig, packet):
    #print("TCP packet: conn: {}, is_orig:{}".format(conn[0], is_orig))
    conn_tuple = conn[0]
    if is_orig:
        packet.sender = "{}:{}".format(conn_tuple[0], conn_tuple[1])
        packet.receiver = "{}:{}".format(conn_tuple[2], conn_tuple[3])
    else: #Flip it
        packet.sender = "{}:{}".format(conn_tuple[2], conn_tuple[3])
        packet.receiver = "{}:{}".format(conn_tuple[0], conn_tuple[1])
    #print("TCP packet: after packet: {}, is_orig:{}".format(packet.sender, packet.receiver))
        
def parse_packet(args):
    packet_info = args[0]
    packet = Packet()

    # Timestamp
    #packet.ts = (packet_info[0] - datetime.datetime(1970, 1, 1)).total_seconds()
    #print(packet.ts)

    # Connection
    parse_conn(packet_info[1], packet)

    # Packet header
    parse_hdr(packet_info[2], packet)

    #print(packet)
    return packet

def parse_tcp_packet(args):
    packet_info = args[0]
    packet = TcpPacket()
    parse_conn(packet_info[1], packet)
    parse_sender_receiver(packet_info[1], packet_info[6], packet)
    packet.packet_len = packet_info[5].value
    packet.protocol_type = "TCP"
    # string with the packets TCP flags
    # S: SYN, F: FIN, R: RST, A: ACK, P: PUSH
    packet.tcp_flag = packet_info[2]
    packet.seq = packet_info[3].value
    packet.ack = packet_info[4].value
    #packet.is_orig = packet_info[7].value
#    packet.payload = packet_info[4]
    return packet

def parse_service_packet(args):
    packet_info = args[0]
    packet = ServicePacket()
        
    packet.service = packet_info[2]
    if packet_info[6] is not None:
        packet_info.is_orig = packet_info[6]
    
    parse_connection(packet_info, packet)

    if packet_info[2] == 'TELNET':
        parse_telnet_packet(packet_info, packet)
        packet.service = 'TELNET'  
    elif packet_info[2] == 'HTTP':
        parse_http_packet(packet_info, packet)
        packet.service = 'HTTP'

    return packet

def parse_connection(pkt_info, pkt):
    orig_h = ''
    orig_p = ''
    resp_h = ''
    resp_p = ''
    if pkt.is_orig == 1:
        orig_h = str(pkt_info[1][0][0])
        orig_p = str(pkt_info[1][0][1])
        resp_h = str(pkt_info[1][0][2])
        resp_p = str(pkt_info[1][0][3])
        pkt.source_macaddress = str(pkt_info[1][1][5])
        pkt.dest_macaddress = str(pkt_info[1][2][5])
    else:
        resp_h = str(pkt_info[1][0][0])
        resp_p = str(pkt_info[1][0][1])
        orig_h = str(pkt_info[1][0][2])
        orig_p = str(pkt_info[1][0][3])
        pkt.source_macaddress = str(pkt_info[1][2][5])
        pkt.dest_macaddress = str(pkt_info[1][1][5])
    pos = orig_p.find('/')
    if pos != -1:
        orig_p = orig_p[:pos]
    pos = resp_p.find('/')
    if pos != -1:
        resp_p = resp_p[:pos]
    pkt.conn = (orig_h, orig_p, resp_h, resp_p)


def parse_telnet_packet(pkt_info, pkt):
    if pkt_info[3] is not None:
        pkt.username = pkt_info[3]
    if pkt_info[4] is not None:
        pkt.password = pkt_info[4]
    if pkt_info[5] is not None:
        pkt.command_line = pkt_info[5]

    if pkt_info[6] is not None:
        pkt.is_orig = pkt_info[6]

def parse_http_packet(pkt_info, pkt):
    if pkt_info[3] is not None:
        pkt.is_orig = pkt_info[3]
    if pkt_info[4] is not None:
        pkt.method = pkt_info[4]
    if pkt_info[5] is not None:
        pkt.uri = pkt_info[5]
    if pkt_info[6] is not None:
        pkt.status_code = pkt_info[6]
    if pkt_info[7] is not None:
        pkt.status_msg = pkt_info[7]
    pkt.service = 'HTTP'

