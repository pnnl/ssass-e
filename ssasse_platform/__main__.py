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

import os
import argparse
import gevent
import logging
import sys
from .ActiveScanningEngine.active_scanner import ActiveScanningEngine 
from .PassiveScanningEngine.evidence_collector import EvidenceCollector
from .InferenceEngine.inference import DeviceIdentificationEngine
from .utils.config_parser import ConfigParser
from .common.rmq_connection import RabbitMqConnection
import time
from os.path import expanduser

_log = logging.getLogger(__name__)
logging.basicConfig(filename="ssasse.log", level=logging.DEBUG)

def log_to_file(file, level=logging.WARNING,
                handler_class=logging.StreamHandler):
    """Direct log output to a file (or something like one)."""
    handler = handler_class(file)
    handler.setLevel(level)
    formatter = logging.Formatter('%(asctime)s %(module)s %(levelname)s: %(message)s')
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)

ready = False
def set_connection_ready():
    _log.debug("ready")
    ready = True

def main(role='collector'):
    """Main method"""
    config_path = os.path.join(os.getcwd(), 'ssasse_platform', 'config.yml')
    config = ConfigParser(config_path)

    print("config: {}".format(config))
    log_to_file(sys.stderr, logging.DEBUG)
    greenlets = []

    home = expanduser("~")
    pid_file = os.path.join(home, "SSASSE_PID")
    _log.debug("PID file: {}, PID: {}".format(pid_file, os.getpid()))
    with open(pid_file, 'w+') as f:
        f.write(str(os.getpid()))
    try:
        roles = config.config_opts.get('roles', [])
        objs = []

        _log.debug("config: {}".format(config))        
        rmq_connection = RabbitMqConnection(config.hostname, config.port, config.rabbitmq_certificates)
        rmq_connection.connect(connection_callback=set_connection_ready)
        
        time.sleep(10)

        _log.debug("connection is ready")

        for role in roles:
            if role == 'passive':
                # Start Evidence Collection Engine
                _log.debug("Starting Evidence Collector")
                objs.append(EvidenceCollector(config, rmq_connection))
            elif role == 'active':
                # Start Active Scanning Engine
                _log.debug("Starting Active Scanning Engine")
                objs.append(ActiveScanningEngine(config, rmq_connection))
            elif role == 'inference':
                # Start Inference Engine
                _log.debug("Starting Inference Engine")
                objs.append(DeviceIdentificationEngine(config, rmq_connection))
            elif role == 'all':
                # Start all
                objs.append(EvidenceCollector(config, rmq_connection))
                objs.append(ActiveScanningEngine(config, rmq_connection))
                objs.append(DeviceIdentificationEngine(config, rmq_connection))
            else:
                _log.error("Unknown role: {}. Exiting...".format(role))
                exit()
            for obj in objs:
                _log.debug("starting worker loop")
                obj.set_connection_ready()
                greenlets.append(gevent.spawn(obj.worker_loop))
        _log.debug("Writing SSASSE process id to pid file")
        gevent.sleep(10)
        gevent.joinall(greenlets)
        _log.debug("SSASSE Shutting down. Removing SSASSE pid file")
        if os.path.exists(pid_file):
            os.remove(pid_file)
    except Exception as e:
        _log.error(e)
        if os.path.exists(pid_file):
            os.remove(pid_file)


if __name__=='__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
