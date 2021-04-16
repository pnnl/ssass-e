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

try:
    import yaml
except ImportError:
    raise RuntimeError('PyYAML must be installed before running this script ')


class ConfigParser(object):
    def __init__(self, config_path):
        self.config_opts = {}
        self.config_path = config_path
        self.load_rmq_config()

    def load_rmq_config(self, config_path=None):
        """
        Loads main  config from config_path
        :param config_path: config path
        :return:
        """
        """Loads the config file if the path exists."""

        with open(self.config_path, 'r') as yaml_file:
            self.config_opts = yaml.safe_load(yaml_file)

    @property
    def internal_ip_range(self):
        return self.config_opts.get('internal-ip-range', None)

    @property
    def ip(self):
        return self.config_opts.get('ip', None)

    @property
    def hostname(self):
        return self.config_opts.get('rabbitmq-host', '127.0.0.1')

    @property
    def port(self):
        return self.config_opts.get('rabbitmq-port', 5672)

    @property
    def site(self):
        return self.config_opts.get('site-name', 'sensor-box1')
    
    @property
    def rabbitmq_certificates(self):
        return self.config_opts.get('rabbitmq-certificates', {})
