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

class DataValue:
    def __init__(self,
                ts=None,  
                holder_ip=None,
                protocol=None,
                uid=None,
                data_type=None,
                index=None,
                value=None,
                is_event=False
                ):
        self.ts = ts
        self.holder_ip = holder_ip 
        self.protocol = protocol 
        self.uid = uid 
        self.data_type = data_type 
        self.index = index 
        self.value = value
        self.is_event = is_event


    def getDict(self):
        rst = {"ts": self.ts,
               "holder_ip": self.holder_ip,
               "service": self.protocol,
               "uid": self.uid,
               "data_type": self.data_type,
               "index": self.index,
               "value": self.value,
               "is_event": self.is_event}
        return rst
            

    def __str__(self):
        return '''
    ts = {0} 
    holder_ip = {1} 
    protocol = {2}
    uid = {3} 
    data_type = {4} 
    index = {5} 
    value = {6}
    is_event = {7}
'''.format(
            datetime.datetime.fromtimestamp(self.ts),
            self.holder_ip,
            self.protocol,
            self.uid,
            self.data_type,
            self.index,
            self.value,
            self.is_event
            ) 

