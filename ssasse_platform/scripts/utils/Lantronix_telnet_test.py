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

import telnetlib
import socket
import time

def Lantronix_get_DeviceInfo(**kwargs):
    """
    This function pulls the relevant device information and returns a dictionary.
    """
    IP=kwargs['TARGET_IPADDR']
    PORT=kwargs['TARGET_PORT']

    i=0

    while(i < 100):
        tn=telnetlib.Telnet(IP,PORT)

        tn.write(b'ID\r\n')

        output=tn.read_until(b"=").decode('ascii')
        print(output)

        tn.write(b'HEL\r\n')

        output2=tn.read_until(b"=").decode('ascii')
        print(output2)

        tn.close()
        time.sleep(5)
        i=i+1


if __name__=='__main__':
    IPAddress_list=['172.17.0.254 2009']
    kwargs={}
    print('\n######\n')
    for device in IPAddress_list:
        argstring= device.split()
        kwargs['TARGET_IPADDR']=argstring[0]
        kwargs['TARGET_PORT']=argstring[1]
        Lantronix_get_DeviceInfo(**kwargs)
        print('\n######\n')
