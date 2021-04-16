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
Decision Tree to make predictions for possible actions to take to
identify vendor, model and firmware version of devices. Device decision 
tree design follows a hierarchical structure.
    Level 1 - Global level decision tree - Set of predictions to find
              vendor, model and firmware version of the device
    Level 2 - Vendor level decision tree - This tree has to be called 
              after Vendor has been identified. It comes up with sequence
              of actions to be taken to find device model based on evidence
              (and previous set of actions)
    Level 3 - Model level decision tree - This tree has to be called after 
              Model has been identified. It comes up with set of actions to 
              be taken to find model firmware version based on evidence
              (and previous set of actions)
'''

from .baseDecisionTree import BaseDecisionTree
import logging

_log = logging.getLogger(__name__)

global_attribute_map = dict()
vendor_attribute_map = dict()
model_attribute_map = dict()

global_attribute_map['MAC'] = {"empty", "yes", "no"}
global_attribute_map['OUILOOKUP'] = {"empty", "yes", "no"}
global_attribute_map['Protocol'] = {"empty", "dnp3", "modbus", "rocplus"}
global_attribute_map['Vendor'] = {"empty", "yes", "no"}
global_attribute_map['Model'] = {"empty", "yes", "no"}
global_attribute_map['Firmware'] = {"empty", "yes", "no"}
global_attribute_map['tcp_scan'] = {"empty", "yes", "no"}
global_attribute_map['READ_ATTR'] = {"empty", "yes", "no"}

vendor_attribute_map['config_scan'] = {"empty", "yes", "no"}
vendor_attribute_map['scada_scan'] = {"empty", "yes", "no"}
vendor_attribute_map['Protocol'] = {"empty", "available"}
vendor_attribute_map['Services'] = {"empty", "available"}
vendor_attribute_map['tcp_scan'] = {"empty", "yes", "no"}
vendor_attribute_map['network_scan'] = {"empty", "yes", "no"}
vendor_attribute_map['Model'] = {"empty", "yes", "no"}

model_attribute_map['config_scan'] = {"empty", "yes", "no"}
model_attribute_map['network_scan'] = {"empty", "yes", "no"}
model_attribute_map['Model'] = {"empty", "sel3530", "sel351", "sel451",
                                "ged20", "ged30", "gen60", "gel90",
                                "roc800", "controlwave", "fb107", "sel rtac",
                                "sage2300", "slc03212n03", "sel 351", "sel 451"}
model_attribute_map['Firmware'] = {"empty", "yes", "no"}

global_training_table_path = "ssasse_platform/InferenceEngine/DecisionTrees/global_device_training_table.csv"
vendor_training_table_path = "ssasse_platform/InferenceEngine/DecisionTrees/vendor_device_training_table.csv"
model_training_table_path = "ssasse_platform/InferenceEngine/DecisionTrees/model_device_training_table.csv"

class DeviceDecisionTree(BaseDecisionTree):
    """
    DeviceDecisionTree class predicts what the next action should be to 
    identify a device based on the incoming evidence and previous 
    predictions
    """
    def __init__(self, profiles, level='global'):
        super(DeviceDecisionTree, self).__init__(profiles)
        self.level = level
        if level == 'global':
            self.attribute_map = global_attribute_map
            self.build_decision_tree(global_training_table_path)
        elif level == 'vendor':
            self.attribute_map = vendor_attribute_map
            self.build_decision_tree(vendor_training_table_path)
        elif level == 'model':
            self.attribute_map = model_attribute_map
            self.build_decision_tree(model_training_table_path)
        else:
            raise ValueError(f'Invalid device decision level: {level}')
        self.build_support_vector()
    
    def build_support_vector(self):
        # Build initial support map
        for key in self.attribute_map:
            self.support_map[key] = "empty"

        combinations = []
        for key, values in self.attribute_map.items():
            for vals in values:
                #_log.debug(key, vals)
                combinations.append(key + '_' + vals)
        
        # Build initial test vector
        for key in combinations:
            if "empty" in key:
                self.support_vector[key] = 1
            else:
                self.support_vector[key] = 0
        #_log.debug("DeviceDecisionTree support vector: {}".format(self.support_vector))

    def predict(self, mysteryEvidence):
        prediction = "NA"
        try:
            for key, val in self.attribute_map.items():
                self.support_map[key] = mysteryEvidence.get(key, 'empty')
            
            self.convert_to_support_vector()

            #_log.debug("support map: {}".format(self.support_map))
            #_log.debug("support vector: {}".format(self.support_vector))
            # Run decision tree using support vector
            prediction = self.predict_decision(self.support_vector)
            prediction = str(prediction[0])
        except Exception as e:
            _log.debug("DeviceDecisionTree.predict() - ERROR: {0}".format(e))

        return prediction


