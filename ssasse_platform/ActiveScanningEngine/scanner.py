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

"""
scanners module

Nessus Scanning is supported using pyTenable to interact with Tenable.sc


"""

import sys

PYTENABLE_AVAILABLE = True
try:
    from tenable.sc import TenableSC
except ImportError:
    print("Please install pyTenable to run Nessus Scans")
    PYTENABLE_AVAILABLE = False

import ssasse_platform.ActiveScanningEngine.nessus_scans.nessus_scans as NessusScanner
import ssasse_platform.ActiveScanningEngine.custom_scans.custom_scans as CustomScanner
import ssasse_platform.ActiveScanningEngine.nmap_scans.nmap_scans as NmapScanner

class Scanner(object):

    """Base Scanner class.

    Abstract class object for different scanners (Tenable, OpenVAS, nmap, etc...)

    """
    def __init__(self):
        """Init a scanner object."""

    def run_scan(self, scan_name, **kwargs):

        """Override me"""

class Custom_Scanner(Scanner):

    def __init__(self):

        super(Custom_Scanner, self).__init__()

    def run_scan(self, scan_name, **kwargs):

        scan = getattr(CustomScanner, scan_name)
        print(scan)
        return scan(**kwargs)

class OpenVAS_Scanner(Scanner):

    def __init__(self):

        super(Custom_Scanner, self).__init__()

    def run_scan(self, scan_name, **kwargs):

        scan = getattr(CustomScanner, scan_name)
        print(scan)
        return scan(**kwargs)

class nmap_Scanner(Scanner):

    def __init__(self):

        super(nmap_Scanner, self).__init__()

    def run_scan(self, scan_name, **kwargs):

        scan = getattr(NmapScanner, scan_name)
        print(scan)
        return scan(**kwargs)
        

class Nessus_Scanner(Scanner):

    def __init__(self):

        super(Nessus_Scanner, self).__init__()

    def run_scan(self, scan_name, **kwargs):

        if PYTENABLE_AVAILABLE:
            scan = getattr(NessusScanner, scan_name)
            return scan(**kwargs)
        else:
            #TODO: Inform Inference Engine Somehow
            print("Could not run scan due ito pyTenable dependency missing!")
            return {'SCAN_NAME': scan_name, 'error': 'pyTenable Dependency Missing!'}

