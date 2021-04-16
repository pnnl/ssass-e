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

class Packet:
    def __init__(self,
                ts=None,
                orig_ip=None,
                resp_ip=None,
                orig_port=None,
                resp_port=None,
                protocol=None,
                tcp_flag=-1,
                service=None,
                packet_len=None,
                fc=None,
                fn=None,
                conn=None
                ):
        self.ts = ts
        self.orig_ip = orig_ip
        self.resp_ip = resp_ip
        self.orig_port = orig_port
        self.resp_port = resp_port
        self.protocol = protocol
        self.tcp_flag = tcp_flag
        self.service = service
        self.packet_len = packet_len
        self.fc = fc
        self.fn = fn
        self.conn = conn

    def getDict(self):
        rst = dict(ts=self.ts,
                orig_ip=self.orig_ip,
                resp_ip=self.resp_ip,
                orig_port=self.orig_port,
                resp_port=self.resp_port,
                protocol=self.protocol,
                tcp_flag=self.tcp_flag,
                service=self.service,
                packet_len=self.packet_len,
                fc=self.fc,
                fn=self.fn,
                conn=self.conn)
        return rst

