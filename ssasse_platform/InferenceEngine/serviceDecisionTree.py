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

''''
Decision Tree to classify services and their vulnerabilities
'''

#from .ssasse_platform.InferenceEngine.baseDecisionTree import BaseDecisionTree
from .baseDecisionTree import BaseDecisionTree
import logging

_log = logging.getLogger(__name__)

attribute_map = dict()
attribute_map['PORT_OPEN'] = {"empty", "yes", "no"}
attribute_map['SERVICE_RUNNING'] = {"empty", "ftp", "telnet", "http", "ntp", "tftp", 
                                    "dnp", "mbap", "iec104", "isotsap", "sixtrak",
                                    "no", "unknown", "pulseaudio", "ssh", 
                                    "remoteanything", "shell", "ldapssl", "radius", "tcpwrapped", "iso-tsap", "iec-104"}
attribute_map['ANONYMOUS_ACCESS'] = {"empty", "yes", "no"}
attribute_map['DEFAULT_ACCESS'] = {"empty", "yes", "no"}

service_training_table_path = "ssasse_platform/InferenceEngine/DecisionTrees/service_training_table.csv"

class ServicesDecisionTree(BaseDecisionTree):
    def __init__(self, profiles, training_table_path=None):
        super(ServicesDecisionTree, self).__init__(profiles)
        self.build_decision_tree(service_training_table_path)
        self.build_support_vector()
    
    def build_support_vector(self):
        # Build initial support map
        for key in attribute_map:
            self.support_map[key] = "empty"

        combinations = []
        for key, values in attribute_map.items():
            for vals in values:
                print(key, vals)
                combinations.append(key + '_' + vals)
        
        # Build initial test vector
        for key in combinations:
            if "empty" in key:
                self.support_vector[key] = 1
            else:
                self.support_vector[key] = 0
        #print("Initial support vector: {}".format(self.support_vector))

    def predict(self, mysteryEvidence):
        prediction = "NA"
        try:
            self.support_map['PORT_OPEN'] = mysteryEvidence.get('PORT_OPEN', 'empty')
            self.support_map['SERVICE_RUNNING'] = mysteryEvidence.get('SERVICE_RUNNING', 'empty')
            self.support_map['ANONYMOUS_ACCESS'] = mysteryEvidence.get('ANONYMOUS_ACCESS', 'empty')
            self.support_map['DEFAULT_ACCESS'] = mysteryEvidence.get('DEFAULT_ACCESS', 'empty')

            self.convert_to_support_vector()

            #print("support map: {}".format(self.support_map))
            #print("support vector: {}".format(self.support_vector))
            # Run decision tree using support vector
            prediction = self.predict_decision(self.support_vector)
            prediction = str(prediction[0])
        except Exception as e:
            print("decision_tree_design.run_decision_tree() - ERROR: {0}".format(e))

        return prediction

def run_decision_tree(mysteryEvidence, decision_tree):
    try:
        # Create new support map based on evidence
        decision_tree.support_map['PORT_OPEN'] = mysteryEvidence.get('PORT_OPEN', 'empty')
        decision_tree.support_map['SERVICE_RUNNING'] = mysteryEvidence.get('SERVICE_RUNNING', 'empty')
        decision_tree.support_map['ANONYMOUS_ACCESS'] = mysteryEvidence.get('ANONYMOUS_ACCESS', 'empty')
        decision_tree.support_map['DEFAULT_ACCESS'] = mysteryEvidence.get('DEFAULT_ACCESS', 'empty')

        decision_tree.convert_to_support_vector()
        
        print("support map: {}".format(decision_tree.support_map))
        print("support vector: {}".format(decision_tree.support_vector)) 
        # Run decision tree using support vector
        prediction = decision_tree.predict_decision(decision_tree.support_vector)
        prediction = str(prediction[0])
                
    except Exception as e:
        print("decision_tree_design.run_decision_tree() - ERROR: {0}".format(e))
        prediction = "NA"
    
    # hard code decision to NA if prediction is in evidence and already set to No
    print("PREDICTION: {0}, MYSTERY_EVIDENCE: {1}".format(prediction, mysteryEvidence))


if __name__ == "__main__":
    profiles=[]
    training_table_path = '/Users/nidd494/Work/SSASSE/service_training_table.csv'    
    decision_tree = ServicesDecisionTree(profiles, training_table_path)    
    # Build mystery evidence
    rawPassiveEvidence = dict()
    rawPassiveEvidence['PORT_OPEN'] = 'yes'
    rawPassiveEvidence['SERVICE_RUNNING'] = 'empty'
    rawPassiveEvidence['ANONYMOUS_ACCESS'] = 'empty'
    rawPassiveEvidence['DEFAULT_ACCESS'] = 'empty'
    prediction = run_decision_tree(rawPassiveEvidence, decision_tree)
 
    rawPassiveEvidence['PORT_OPEN'] = 'yes'
    rawPassiveEvidence['SERVICE_RUNNING'] = 'yes'
    rawPassiveEvidence['ANONYMOUS_ACCESS'] = 'empty'
    rawPassiveEvidence['DEFAULT_ACCESS'] = 'empty'

    prediction = run_decision_tree(rawPassiveEvidence, decision_tree)
    rawPassiveEvidence['PORT_OPEN'] = 'yes'
    rawPassiveEvidence['SERVICE_RUNNING'] = 'yes'
    rawPassiveEvidence['ANONYMOUS_ACCESS'] = 'yes'
    rawPassiveEvidence['DEFAULT_ACCESS'] = 'empty'
    prediction = run_decision_tree(rawPassiveEvidence, decision_tree)
    
    rawPassiveEvidence['PORT_OPEN'] = 'yes'
    rawPassiveEvidence['SERVICE_RUNNING'] = 'yes'
    rawPassiveEvidence['ANONYMOUS_ACCESS'] = 'yes'
    rawPassiveEvidence['DEFAULT_ACCESS'] = 'no'
    prediction = run_decision_tree(rawPassiveEvidence, decision_tree)

    rawPassiveEvidence['PORT_OPEN'] = 'yes'
    rawPassiveEvidence['SERVICE_RUNNING'] = 'no'
    rawPassiveEvidence['ANONYMOUS_ACCESS'] = 'empty'
    rawPassiveEvidence['DEFAULT_ACCESS'] = 'empty'    
    prediction = run_decision_tree(rawPassiveEvidence, decision_tree)
