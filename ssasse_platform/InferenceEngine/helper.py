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

import logging
logger = logging.getLogger(__name__)
def printD(m):
    logger.debug(m)

def sanitizeWhitespace(val):
    val = str(val)
    val = "".join(val.split())
    return val

def sanitize(val):
    val = str(val)
    val = val.strip()
    val = "".join(val.split())
    val = "".join(e for e in val if e.isalnum() or e=='_' or e==':' or e=='.' or e =='/')
    return val

def sanitizeKey(key):
    key = str(key)
    key = key.upper()
    key = key.strip()
    key = "".join(key.split())
    key = "".join(e for e in key if e.isalnum() or e=='_')
    return key

def sanitizeTable(table):
    table = str(table)
    table = table.strip()
    table = "".join(table.split())
    table = "".join(e for e in table if e.isalnum() or e=='_')
    return table

def sanitizeVal(val):
    val = str(val)
    val = val.lower()
    val = val.strip()
    val = "".join(val.split())
    val = "".join(e for e in val if e.isalnum() or e=='_' or e==':' or e=='.' or e=='/')
    return val

def breakDownDict(myDict, path = "", newDict = {}):
    for k,v in myDict.items():
        if path != "":
            newPath = path+"_"+k
        else:
            newPath = k
        if type(v) is dict:
            newDict[newPath] = list(v.keys())
            breakDownDict(v,newPath,newDict)
        else:
            newDict[newPath] = v
    return newDict

def newbreakDownDict(myDict, path='', newDict={}):
    for k,v in myDict.items():
        if path != "":
            newPath = path+"_"+k
        else:
            newPath = k
        if isinstance(v, dict):
            #newDict[newPath] = list(v.keys())
            breakDownDict(v,newPath,newDict)
        else:
            newDict[newPath] = v
    return newDict

def getNested(myDict, targetKey):
        found = False
        keyName = singleInList(targetKey, myDict.keys())

        if keyName != False:
            found = myDict[keyName]

        else:
            for keyName in myDict.keys():
                if isinstance(myDict[keyName], dict):
                    found = getNested(myDict[keyName], targetKey)
                    if found != False:
                        break

        return found

def printDict(myDict, depth = 0):
    str = ""
    if depth==0:
        str = str+("{\n")
    tabsize = 2
    for k,v in myDict.items():
        if type(v) is dict:
            str = str+(" "*(depth+1)*tabsize + "{0}: ".format(k) + "{\n")
            printDict(v, depth+1)
            str=str+(" "*(depth+1)*tabsize + "}\n")
        else:
            str=str+(" "*(depth+1)*tabsize + "{0}: {1}\n".format(k,v))
    if depth==0:
        str=str+("}\n")
    return str

def singleInList(single, list):
    found = False

    newSingle = sanitizeVal(single)
    for item in list:
        newItem = sanitizeVal(item)
        if newSingle == newItem:
            found = item
            break

    return found

def compareSingle(single1, single2):
    match = False

    newSingle1 = sanitizeVal(single1)
    newSingle2 = sanitizeVal(single2)

    if newSingle1 == newSingle2:
        match = True

    return match

