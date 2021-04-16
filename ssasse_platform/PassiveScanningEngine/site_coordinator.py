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

'''
Evidence Manager acts as the main server. It contains
'''

import gevent
import os
import logging
from ..utils.config_parser import ConfigParser
from ..common.actor import Actor

_log = logging.getLogger(__name__)


class SiteCoordinator(Actor):
    def __init__(self, config):
        super(SiteCoordinator, self).__init__(config)
        _log.debug("Site Coordinator Constructor")
        self.collector_greenlet = gevent.spawn(self.setup_evidence_subscription)

    def setup_evidence_subscription(self):
        while not self.connection_ready:
            gevent.sleep(0.5)
        # Subscribe to receive protocol detection messages from all the collectors (sensor boxes)
        subscriptions = [dict(prefix='packet', queue_name='packet_queue', callback=self.evidence_callback)]
        self.add_subscriptions(subscriptions)

    def evidence_callback(self, topic, message):
        # store the message count
        _log.debug("Evidence message received: From: {}, Message: {}".format(topic, message))
        # Republish to other actors (ProbabilityEngine, Historian, StatisticalEngine)
        topic.replace('packet', 'evidence')
        self.publish_evidence(topic, message)
