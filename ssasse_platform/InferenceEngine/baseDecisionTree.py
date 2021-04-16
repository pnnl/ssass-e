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
Base class implementation for Decision Tree (Uses DecisionTreeClassifier from sklearn library)
'''

import pandas as pd
import json
from sklearn import tree
from sklearn.externals.six import StringIO  

class BaseDecisionTree():
    """
    BaseDecisionTree class provides common apis to 
        - Create decision tree and train the model based on the training vector
        - Build a support vector
        - Prediction utility method
        - Plot decision tree graph
    """
    def __init__(self, profiles):
        self.profiles = profiles
        self.model = None
        self.model_train = None
        self.support_map = dict()
        self.support_vector = dict()

    def build_decision_tree(self, training_table_path):
        table = pd.read_csv(training_table_path)
        attr = table.columns.tolist()
        print(attr)
        try:
            attr.remove('Unnamed: 0')
        except ValueError:
            pass
        attr.remove('DECISION')
        # Create training dataset
        training_dataset = pd.get_dummies(table[attr])
        self.columns = training_dataset.columns
        print(self.columns)
        training_dataset.to_csv('xxx_training_dataset.csv')
        
        # Create DecisionTree and train the model
        model = tree.DecisionTreeClassifier(criterion='entropy', random_state=48, presort=True)
        print("Training the model")
        self.model_train = model.fit(training_dataset, table['DECISION'])
        
    def plot_decision_tree(self, model_train, one_hot_data, plot_name):
        import pydot_ng as pydot
        dot_data = StringIO()
        tree.export_graphviz(model_train, out_file=dot_data, 
                            feature_names=list(one_hot_data.columns.values), rounded=True, 
                            filled=True)       

        graph = pydot.graph_from_dot_data(dot_data.getvalue())
        graph.write_pdf("%s.pdf"%plot_name)

    def predict_decision(self, test_vector):
        tv = []
        for col in self.columns:
            tv.append(test_vector[col])
        prediction = self.model_train.predict([tv])
        return prediction

    def update_support_vector(self):
        self.convert_to_support_vector()

    def convert_to_support_vector(self):
        try:
            for key, value in self.support_map.items():
                match_keys = []
                for k in self.support_vector.keys():
                    if k.startswith(key):
                        match_keys.append(k)
                key_to_set = key + '_' + value
                self.support_vector[key_to_set] = 1
                #printD(key_to_set)
                try:
                    match_keys.remove(key_to_set)
                except ValueError:
                    print("Value Error:{}".format(key_to_set))
                for ky in match_keys:
                    self.support_vector[ky] = 0
        except KeyError as e:
            print("KeyError: {}".format(e))
        #printD("******** {}".format(self.support_vector))
