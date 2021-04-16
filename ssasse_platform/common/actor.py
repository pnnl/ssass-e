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

import gevent
import logging
from .rmq_connection import RabbitMqConnection

_log = logging.getLogger(__name__)

class Actor(object):
    '''

    '''
    def __init__(self, config, rmq_connection=None):
        _log.debug("Actor Constructor")
        self._config = config
        self.connection_ready=False
        self.site_name = config.site
        if rmq_connection == None:
            self._connection = RabbitMqConnection(config.hostname, config.port, config.certificates)
        else:
            self._connection = rmq_connection
#        self._connection.connect(connection_callback=self.set_connection_ready)
        self.publish_messages = list()

    def publish_action(self, action):
        self._connection.send_message(action)

    def publish_message(self, topic, message):
        self._connection.send_message(topic, message)

    def publish_evidence(self, topic, evidence):
        self._connection.send_message(topic, evidence)

    def publish_results(self, topic, evidence):
        self._connection.send_message(topic, evidence)

    def publish_request(self, topic, message):
        self._connection.send_message(topic, message)

    def publish_internal(self, topic, evidence):
        self._connection.send_message(topic, evidence)

    def add_subscriptions(self, subscriptions):
        for subscription in subscriptions:
            try:
                prefix = subscription['prefix']
                prefix = prefix + '.#'
                callback = subscription['callback']
                queue_name = self.site_name + '-' + subscription['queue_name']
            except KeyError as e:
                _log.debug("Missing key in subscriptions:{}".format(e))
            self._connection.create_queue(prefix=prefix, queue_name=queue_name, callback=callback)

    def set_connection_ready(self):
        self.connection_ready = True

    def worker_loop(self):
        _log.debug("In worker loop ")
        while True:
            try:
                for item in self.publish_messages:
                    self.publish_request(item[0], item[1])
                self.publish_messages.clear()
                gevent.sleep(1)
            except KeyboardInterrupt:
                _log.debug("KeyboardInterrupt occured. Doing a clean exit!")
                if self.connection_ready:
                    self._connection.close_connection()
                break
