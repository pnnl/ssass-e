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

import json
import logging
logger = logging.getLogger(__name__)
DEBUG = True
def printD(m):
    if DEBUG:
        logger.debug(m)
        print(m)

from . import helper
profiles_path = "ssasse_platform/InferenceEngine/Profiles/"

##########################################################
# jaccardSimilarity()
##########################################################z
def jaccardSimilarity(mysteryEvidence, profile):
    #printD("similarityScore.jaccardSimilarity()")
    try:
        fr = open("{0}Weights/ALL.json".format(profiles_path), "r", encoding="utf-8")
        weights = json.loads(fr.read())
        weights = helper.breakDownDict(weights)
        fr.close()
    except:
        weights = {}

    mismatches = {}
    matches = {}
    total = {}

    ignoreKeys = []

    for k1,v1 in mysteryEvidence.items():
        if not helper.singleInList(k1, ignoreKeys):
            for item in v1:
                k1ProfileKey = helper.singleInList(k1, profile.keys())
                if k1ProfileKey:
                    # MATCH
                    if helper.singleInList(item, profile[k1ProfileKey]):
                        if not helper.singleInList(k1, matches.keys()):
                            matches[k1] = set()
                        if not helper.singleInList(item, matches[k1]):
                            matches[k1].add(item)
                    # MISMATCH
                    else:
                        if not helper.singleInList(k1, mismatches.keys()):
                            mismatches[k1] = set()
                        if not helper.singleInList(item, mismatches[k1]):
                            mismatches[k1].add(item)
                # TOTAL
                if not helper.singleInList(k1, total.keys()):
                    total[k1] = set()
                if not helper.singleInList(item, total[k1]):
                    total[k1].add(item)

    for k2,v2 in profile.items():
        if not helper.singleInList(k2, ignoreKeys):
            for item in v2:
                k2MEKey = helper.singleInList(k2, mysteryEvidence.keys())
                if k2MEKey:
                    # MATCH
                    if helper.singleInList(item, mysteryEvidence[k2MEKey]):
                        if not helper.singleInList(k2, matches.keys()):
                            matches[k2] = set()
                        if not helper.singleInList(item, matches[k2]):
                            matches[k2].add(item)
                    # MISMATCH
                    else:
                        if not helper.singleInList(k2, mismatches.keys()):
                            mismatches[k2] = set()
                        if not helper.singleInList(item, mismatches[k2]):
                            mismatches[k2].add(item)

                # TOTAL
                #if k2 not in total:
                #    total[k2] = set()
                #total[k2].add(item)

    bigTotal = 0.0
    for key,val in total.items():
        weight = 1.0
        weightsKey = helper.singleInList(key, weights.keys())
        if weightsKey:
            weight = float(weights[weightsKey])
        if helper.singleInList(key, matches.keys()):
            bigTotal = bigTotal + (weight * float(len(val)))
        elif helper.singleInList(key, mismatches.keys()):
            bigTotal = bigTotal + (weight * float(len(val)))
        else:
            bigTotal = bigTotal + (0.5 * float(len(val)))

    similarityScore = 0.0
    for key,val in matches.items():
        weight = 1.0
        weightsKey = helper.singleInList(key, weights.keys())
        if weightsKey:
            weight = float(weights[weightsKey])
        semiScore = (weight * float(len(val))) / (bigTotal)
        similarityScore = similarityScore + semiScore

    #printD("similarityScore() - mismatches: {0}, matches: {1}, total: {2}".format(mismatches, matches, total))
    return similarityScore
