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

from . import helper

import logging
logger = logging.getLogger(__name__)
DEBUG = True
def printD(m):
    if DEBUG:
        logger.debug(m)

import json

def decisionSimple(mysteryDevice, mysteryEvidence):
    categoryOrder = ["OUI_Lookup", "config_scan", "scada_scan", "tcp_scan", "network_scan"]
    knownVendors = ["sel", "ge", "schneider", "emerson", "redlioninc"]
    #printD("decisionSimple.decision()")
    chosenScan = "NA"

    if "TARGET_MACADDR" in mysteryEvidence:
        if not helper.singleInList("OUI_Lookup", mysteryEvidence.keys()):
            chosenScan = "OUI_Lookup"

        elif "VENDOR" in mysteryEvidence.keys() and helper.singleInList(mysteryEvidence["VENDOR"][0], knownVendors) != False:
            for categoryName in categoryOrder:
                if not helper.singleInList(categoryName, mysteryEvidence.keys()):
                    chosenScan = categoryName
                    break

    printD("decisionSimple.decision() - ip: {0}, chosenScan: {1}, evidence: {2}".format(mysteryDevice, chosenScan, mysteryEvidence))
    return chosenScan
