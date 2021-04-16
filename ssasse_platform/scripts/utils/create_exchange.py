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

import requests
import json
import socket

host=socket.gethostname()
port=15672
print(host)

params = dict(durable=True, type='topic')

def create_exch(body, user, password):
    exchange='ssasse'
    vhost='ssasse'
    url = "http://{host}:{port}/api/exchanges/{vhost}/{exchange}".format(host=host, port=port, vhost=vhost, exchange=exchange)
    print(url, body)
    req = requests.put(url, data=json.dumps(body), headers={"Content-Type": "application/json"}, auth=(user, password))
    #res = grequests.map([req])
    #res[0].raise_for_status()
    print(req.status_code)

def create_user(user, password):
    url = "http://{host}:{port}/api/users/{user}".format(host='localhost', port=port, user=user)
    body = dict(password=password, tags='administrator')
    response = requests.put(url, data=json.dumps(body), auth=('guest', 'guest'))
    print(response.status_code)

def create_vhost(user, password, virtual_host):
    url = "http://{host}:{port}/api/vhosts/{vhost}".format(host=host,port=port,vhost=virtual_host)
    req = requests.put(url, auth=(user, password))
    print(req.status_code)

try:
    print("creating user")
    create_user('collector', 'collector')
    print("creating vhost")
    create_vhost('collector', 'collector', 'ssasse')
    print("creating exchange")
    create_exch(params, 'collector', 'collector')
except Exception as e:
    print(e)

