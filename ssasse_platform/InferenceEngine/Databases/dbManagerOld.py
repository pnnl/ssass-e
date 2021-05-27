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

import sqlite3
from .. import helper

# DB file
sqlite_path = "ssasse_platform/InferenceEngine/Databases/"

import logging
logger = logging.getLogger(__name__)
DEBUG = False
def printD(m):
    if DEBUG:
        logger.debug(m)

import multiprocessing

class DBManager():
    def __init__(self):
        printD("dbManager.__init__()")
        self.lock = multiprocessing.Lock()
        self.vulnLock = multiprocessing.Lock()

    ###############################################################################
    # create(sqlite_file) 
    # Wipe DB and create it from scratch. Will have no records in the tables. 
    ###############################################################################
    def create(self, sqlite_file):
        #printD("dbManager.create()")
        self.lock.acquire()
        try:
            # wipe file
            printD("dbManager - creating db file from scratch: {0}".format(sqlite_file))
            f = open("{0}{1}".format(sqlite_path,sqlite_file), "w+")
            f.close()

            conn = sqlite3.connect("{0}{1}".format(sqlite_path,sqlite_file))
            c = conn.cursor()

            # Identifier
            printD("dbManager.create() - create table: identifier")
            c.execute("""CREATE TABLE IF NOT EXISTS identifier (
                identifier_id integer PRIMARY KEY,
                identifier_value text NOT NULL UNIQUE)""")

            conn.commit()
            conn.close()

        except Exception as e:
            printD("dbManager.create() - ERROR: {0}".format(e))
        finally:
            self.lock.release()

        return 0

    ##########
    #
    ##########
    def insertVulnerabilityTableEntry(self, sqlite_file, vuln_sqlite_file, identifier, vulnDict):
        self.vulnLock.acquire()
        try:
            allVulnIDs = allIdentifiers(vuln_sqlite_file)
            vulnID = "V_{0}".format(len(allVulnIDs)+1)
            for key,val in vulnDict.items():
                vulnDict[key] = [val]
            self.insert(vuln_sqlite_file, vulnID, vulnDict)
            self.insert(sqlite_file, identifier, {"VULNERABILITIES": [vulnID]})
        except Exception as e:
            printD("dbManager.insertVuln() - ERROR: {0}".format(e))
        finally:
            self.vulnLock.release()

    ###############################################################################
    # insert(sqlite_file, identifier_value, attributeDict)
    # insert data for identifier profile, given identifier name and dict of attribute
    ###############################################################################
    def insert(self, sqlite_file, identifier_value, attributeDict):
        #printD("dbManager.insert()")
        self.lock.acquire()
        try:
            returnResult = 1

            # check file exists
            f = open("{0}{1}".format(sqlite_path,sqlite_file), "a+")
            f.close()

            conn = sqlite3.connect("{0}{1}".format(sqlite_path,sqlite_file))
            c = conn.cursor()

            # check if table exists for identifier
            c.execute("""SELECT EXISTS(SELECT name FROM sqlite_master WHERE type='table' AND name = ?)""", ("identifier",))
            result = c.fetchone()[0]

            #if result != 0:
            #    printD("000SELECT EXISTS(SELECT name FROM sqlite_master WHERE type")

            if result == 0:
                printD("dbManager.insert() - create table: identifier")
                c.execute("""CREATE TABLE IF NOT EXISTS identifier (
                    identifier_id integer PRIMARY KEY,
                    identifier_value text NOT NULL UNIQUE)""")
                returnResult = 0

            # check if record exists for identifier 
            c.execute("""SELECT EXISTS(SELECT 1 FROM identifier WHERE identifier_value = ?)""", (identifier_value,))
            result = c.fetchone()[0]

            #if result != 0:
            #    printD("111SELECT EXISTS(SELECT 1 FROM identifier WHERE identifier_value = ?)")

            # if not, insert 
            if result == 0:
                printD("dbManager.insert() - insert identifier: {0}".format(identifier_value))
                c.execute("""INSERT INTO identifier(identifier_value) VALUES(?)""", (identifier_value,))
                returnResult = 0

            # get identifier_id
            c.execute("""SELECT identifier_id FROM identifier WHERE identifier_value = ?""", (identifier_value,))
            identifier_id = c.fetchone()[0]

            for table,values in attributeDict.items():
                table = helper.sanitizeTable(table)

                # check if table exists for attribute key (table name)
                c.execute("""SELECT EXISTS(SELECT name FROM sqlite_master WHERE type='table' AND name = ?)""", (table,))
                result = c.fetchone()[0]

                #if result != 0:
                #    printD("22SELECT EXISTS(SELECT name FROM sqlite_master WHERE type='table' AND name = ?)")

                # if not, create
                if result == 0:
                    printD("dbManager.insert() - create table: {0}".format(table))
                    c.execute("""CREATE TABLE IF NOT EXISTS {0} (
                            {0}_id integer PRIMARY KEY,
                            {0}_value text NOT NULL UNIQUE)""".format(table))
                    c.execute("""CREATE TABLE IF NOT EXISTS {0}_{1} (
                            {0}_id integer NOT NULL,
                            {1}_id integer NOT NULL,
                            FOREIGN KEY ({0}_id) REFERENCES {0}({0}_id),
                            FOREIGN KEY ({1}_id) REFERENCES {1}({1}_id),
                            PRIMARY KEY ({0}_id, {1}_id))""".format("identifier", table))
                    returnResult = 0

                # insert values into table
                for value in values:
                    #value = helper.sanitizeWhitespace(value)
                    value = str(value).strip()

                    # check if value exists in table
                    c.execute("""SELECT EXISTS(SELECT 1 FROM {0} WHERE {0}_value = ?)""".format(table), (value,))
                    result = c.fetchone()[0]

                    #if result != 0:
                    #    printD("**SELECT EXISTS(SELECT 1 FROM {0} WHERE {0}_value = ?)**")

                    if result == 0:
                        printD("dbManager.insert() - insert table:value: {0}:{1}".format(table, value))
                        c.execute("""INSERT INTO {0}({0}_value) VALUES(?)""".format(table), (value,))
                        returnResult = 0

                    # get attribute_id
                    c.execute("""SELECT {0}_id FROM {0} WHERE {0}_value = ?""".format(table), (value,))
                    attribute_id = c.fetchone()[0]

                    #check if identifier_id,attribute_id pair exists in joined table
                    c.execute("""SELECT EXISTS(SELECT 1 FROM identifier_{0} WHERE identifier_id = ? AND {0}_id = ?)""".format(table), (identifier_id,attribute_id))
                    result = c.fetchone()[0]

                    #if result != 0:
                    #    printD("*****SELECT EXISTS(SELECT 1 FROM identifier_{0} WHERE identifier_id = ?****")
                    if result == 0:
                        # insert id pair into joined table
                        printD("dbManager.insert() - insert table:value: identifier_{0}:{1},{2}".format(table, identifier_id,attribute_id))
                        c.execute("""INSERT INTO identifier_{0} VALUES(?,?)""".format(table), (identifier_id, attribute_id,))
                        returnResult = 0

            conn.commit()
            conn.close()

        except Exception as e:
            printD("dbManager.insert() - ERROR: {0} - identifier_value: {1} - attributeDict: {2}".format(e, identifier_value, attributeDict))
        finally:
            self.lock.release()

        return returnResult

    ###############################################################################
    # removeIdentifier()
    # removes all traces of an identifier from the entire DB
    ###############################################################################
    def removeIdentifier(self, sqlite_file, identifier_value):
        self.lock.acquire()
        try:
            #TODO implement it
            pass
        except Exception as e:
            printD("dbManager.removeIdentifier() - ERROR: {0} - identifier_value: {1}".format(e, identifier_value))
        finally:
            self.lock.release()

    ###############################################################################
    # removeKey()
    # removes all traces of an identifier from a identifier_attribute table
    ###############################################################################
    def removeKey(self, sqlite_file, identifier_value, attribute_key):
        #printD("dbManager.removeKey()")
        self.lock.acquire()
        try:
            returnResult = 1

            # check file exists
            f = open("{0}{1}".format(sqlite_path,sqlite_file), "a+")
            f.close()

            conn = sqlite3.connect("{0}{1}".format(sqlite_path,sqlite_file))
            c = conn.cursor()

            # check if table exists for identifier
            c.execute("""SELECT EXISTS(SELECT name FROM sqlite_master WHERE type='table' AND name = ?)""", ("identifier",))
            result = c.fetchone()[0]

            if result != 0:
                # check if record exists for identifier 
                c.execute("""SELECT EXISTS(SELECT 1 FROM identifier WHERE identifier_value = ?)""", (identifier_value,))
                result = c.fetchone()[0]

                # 
                if result != 0:

                    # get identifier_id
                    c.execute("""SELECT identifier_id FROM identifier WHERE identifier_value = ?""", (identifier_value,))
                    identifier_id = c.fetchone()[0]
                    table = helper.sanitizeTable(attribute_key)

                    # check if table exists for attribute_key (table name)
                    c.execute("""SELECT EXISTS(SELECT name FROM sqlite_master WHERE type='table' AND name = ?)""", (table,))
                    result = c.fetchone()[0]

                    if result != 0:
                        printD("dbManager.removeKey() - delete table: {0} from identifier: {1}".format(table,identifier_value))

                        c.execute("""DELETE FROM identifier_{0} WHERE identifier_id = ?""".format(table), (identifier_id,))
                        returnResult = 0

                        conn.commit()

            conn.close()

        except Exception as e:
            printD("dbManager.removeKey() - ERROR: {0} - identifier_value: {1} - attribute_key: {2}".format(e,identifier_value,attribute_key))
        finally:
            self.lock.release()

        return returnResult

    ###############################################################################
    # removeVal()
    # removes an exact pair from a identifier_attribute table
    ###############################################################################
    def removeVal(self, sqlite_file, identifier_value, attribute_key, attribute_value):
        #printD("dbManager.removeVal()")
        self.lock.acquire()
        try:
            returnResult = 1

            # check file exists
            f = open("{0}{1}".format(sqlite_path,sqlite_file), "a+")
            f.close()

            conn = sqlite3.connect("{0}{1}".format(sqlite_path,sqlite_file))
            c = conn.cursor()

            # check if table exists for identifier
            c.execute("""SELECT EXISTS(SELECT name FROM sqlite_master WHERE type='table' AND name = ?)""", ("identifier",))
            result = c.fetchone()[0]

            if result != 0:
                # check if record exists for identifier 
                c.execute("""SELECT EXISTS(SELECT 1 FROM identifier WHERE identifier_value = ?)""", (identifier_value,))
                result = c.fetchone()[0]

                # if not, return
                if result != 0:
                    # get identifier_id
                    c.execute("""SELECT identifier_id FROM identifier WHERE identifier_value = ?""", (identifier_value,))
                    identifier_id = c.fetchone()[0]
                    table = helper.sanitizeTable(attribute_key)
                    #attribute_value = helper.sanitizeWhitespace(attribute_value)
                    attribute_value = str(attribute_value).strip()

                    # check if table exists for attribute_key (table name)
                    c.execute("""SELECT EXISTS(SELECT name FROM sqlite_master WHERE type='table' AND name = ?)""", (table,))
                    result = c.fetchone()[0]

                    if result != 0:
                        printD("dbManager.removeVal() - delete table: {0} from identifier: {1}".format(table,identifier_value))

                        # get attribute_id
                        c.execute("""SELECT {0}_id FROM {0} WHERE {0}_value = ?""".format(table), (attribute_value,))
                        attribute_id = c.fetchone()[0]

                        c.execute("""DELETE FROM identifier_{0} WHERE identifier_id = ? AND {0}_id = ?""".format(table), (identifier_id, attribute_id))
                        returnResult = 0

                        conn.commit()

            conn.close()

        except Exception as e:
            printD("dbManager.removeVal() - ERROR: {0}, identifier_value: {1}, attribute_key: {2}, attribute_value: {3}".format(e,identifier_value,attribute_key,attribute_value))
        finally:
            self.lock.release()

        return returnResult

###############################################################################
# allIdentifiers(sqlite_file)
# returns all identifier_values in db
###############################################################################
def allIdentifiers(sqlite_file):
    #printD("dbManager.allIdentifiers()")
    returnResult = []

    try:

        # check file exists
        f = open("{0}{1}".format(sqlite_path,sqlite_file), "a+")
        f.close()

        conn = sqlite3.connect("{0}{1}".format(sqlite_path,sqlite_file))
        c = conn.cursor()

        # check if table exists for identifier
        c.execute("""SELECT EXISTS(SELECT name FROM sqlite_master WHERE type='table' AND name = ?)""", ("identifier",))
        result = c.fetchone()[0]

        if result != 0:
            # get all identifier values
            c.execute("""SELECT identifier_value FROM identifier""")
            result = c.fetchall()
            for item in result:
                returnResult.append(item[0])

        conn.close()

    except Exception as e:
        printD("dbManager.allIdentifiers() - ERROR: {0}".format(e))

    return returnResult

###############################################################################
# select(sqlite_file, identifier_value)
# returns all info given a identifier_value
###############################################################################
def select(sqlite_file, identifier_value):
    #printD("dbManager.select()")
    try:
        returnResult = {}

        # check file exists
        f = open("{0}{1}".format(sqlite_path,sqlite_file), "a+")
        f.close()

        conn = sqlite3.connect("{0}{1}".format(sqlite_path,sqlite_file))
        c = conn.cursor()

        # check if record exists for identifier 
        c.execute("""SELECT EXISTS(SELECT 1 FROM identifier WHERE identifier_value = ?)""", (identifier_value,))
        result = c.fetchone()[0]

        if result != 0:
            # get identifier_id
            c.execute("""SELECT identifier_id FROM identifier WHERE identifier_value = ?""", (identifier_value,))
            identifier_id = c.fetchone()[0]

            # get all tables
            c.execute("""SELECT name FROM sqlite_master WHERE type='table' AND name != ?""", ("identifier",))
            r = c.fetchall()
            tableList = []

            for table in r:
                if "identifier_" not in table[0]:
                    tableList.append(table[0])

            for table in tableList:
                c.execute("""SELECT t.{0}_value FROM {0} t
                        LEFT JOIN identifier_{0} dt ON dt.{0}_id = t.{0}_id
                        WHERE dt.identifier_id = ?""".format(table), (identifier_id,))
                r = c.fetchall()
                if len(r) > 0:
                    tempList = []
                    for item in r:
                        tempList.append(item[0])
                    returnResult[table] = tempList

        conn.close()

    except Exception as e:
        printD("dbManager.select() - ERROR: {0} - identifier_value: {1}".format(e, identifier_value))

    return returnResult

###############################################################################
# compare(file1, dev1, file2, dev2)
# compares a identifier profile to IP record (collected attribute)
# returns {ev1: {d1: v1, d2: v1}, ev2: {d1: v3, d2: v4}, ...}
###############################################################################
def compare(sqlite_file1, identifier_value1, sqlite_file2, identifier_value2):
    #printD("dbManager.compare()")
    try:
        returnResult = {}

        results1 = select(sqlite_file1, identifier_value1)
        results2 = select(sqlite_file2, identifier_value2)

        for ev,val in results1.items():
            if ev not in returnResult:
                returnResult[ev] = {}
            returnResult[ev][identifier_value1] = val

        for ev,val in results2.items():
            if ev not in returnResult:
                returnResult[ev] = {}
            returnResult[ev][identifier_value2] = val

    except Exception as e:
        printD("dbManager.compare() - ERROR: {0} - identifier_value1: {1} - identifier_value2: {2}".format(e,identifier_value1,identifier_value2))

    return returnResult
