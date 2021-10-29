#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2021 Pierre LALET <pierre@droids-corp.org>
#
# IVRE is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# IVRE is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with IVRE. If not, see <http://www.gnu.org/licenses/>.


"""
This sub-module contains data to match Windows versions to build numbers
"""

# Sources
# https://www.gaijin.at/en/infos/windows-version-numbers
# https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions
WINDOWS_VERSION_TO_BUILD = {
    "Windows NT 4.0": "4.0.1381",
    "Windows 2000": "5.0.2195",
    "Windows 5.0": "5.0.2195",
    "Windows Server 2003 3790": "5.2.3790",
    "Windows Server 2003 3790 Service Pack 2": "5.2.3790",
    "Windows Server 2003 3790 Service Pack 1": "5.2.3790.1180",
    "Windows Server 2003 R2 3790 Service Pack 2": "5.2.3790",
    "Windows Server (R) 2008 Enterprise 6001 Service Pack 1": "6.0.6001",
    "Windows Server (R) 2008 Enterprise 6002 Service Pack 2": "6.0.6002",
    "Windows Server (R) 2008 Enterprise 6003 Service Pack 2": "6.0.6003",
    "Windows Server (R) 2008 Standard 6002 Service Pack 2": "6.0.6003",
    "Windows Server 2008 R2 Enterprise 7600": "6.1.7600",
    "Windows Server 2008 R2 Enterprise 7601 Service Pack 1": "6.1.7601",
    "Windows Server 2008 R2 Standard 7601 Service Pack 1": "6.1.7601",
    "Windows Web Server 2008 R2 7601 Service Pack 1": "6.1.7601",
    "Windows XP": "5.1.2600",
    "Windows 5.1": "5.1.2600",
    "Windows XP 3790 Service Pack 1": "5.1.2600.1105-1106",  # Lan Manager Windows XP 5.2
    "Windows XP 3790 Service Pack 2": "5.1.2600.2180",  # Lan Manager Windows XP 5.2
    "Windows Vista (TM) Enterprise 6000": "6.0.6000",
    "Windows Vista (TM) Enterprise 6001 Service Pack 1": "6.0.6001",
    "Windows Vista (TM) Enterprise 6002 Service Pack 2": "6.0.6002",
    "Windows 7 Enterprise 7600": "6.1.7600",
    "Windows 7 Professional 7600": "6.1.7600",
    "Windows 7 Enterprise 7601 Service Pack 1": "6.1.7601",
    "Windows 7 Professional 7601 Service Pack 1": "6.1.7601",
    "Windows 8 Enterprise Evaluation 9200": "6.2.9200",
    "Windows 8.1 Enterprise 9600": "6.3.9200",
    "Windows 10 Enterprise 10240": "10.0.10240",
    "Windows 10 Enterprise 2015 LTSB 10240": "10.0.10240",
    "Windows 10 Enterprise 10586": "10.0.10586",
    "Windows 10 Enterprise 14393": "10.0.14393",
    "Windows 10 Enterprise 2016 LTSB 14393": "10.0.14393",
    "Windows 10 Enterprise 15063": "10.0.15063",
    "Windows 10 Enterprise 16299": "10.0.16299",
    "Windows 10 Enterprise 17134": "10.0.17134",
    "Windows 10 Enterprise 17763": "10.0.17763",
    "Windows 10 Enterprise LTSC 2019 17763": "10.0.17763",
    "Windows 10 Enterprise 18362": "10.0.18362",
    "Windows 10 Enterprise 18363": "10.0.18363",
    "Windows 10 Enterprise 19041": "10.0.19041",
    "Windows 10 Enterprise Evaluation 10240": "10.0.10240",
    "Windows 10 Enterprise Evaluation 2015 LTSB 10240": "10.0.10240",
    "Windows 10 Enterprise Evaluation 10586": "10.0.10586",
    "Windows 10 Enterprise Evaluation 14393": "10.0.14393",
    "Windows 10 Enterprise Evaluation 2016 LTSB 14393": "10.0.14393",
    "Windows 10 Enterprise Evaluation 15063": "10.0.15063",
    "Windows 10 Enterprise Evaluation 16299": "10.0.16299",
    "Windows 10 Enterprise Evaluation 17134": "10.0.17134",
    "Windows 10 Enterprise Evaluation 17763": "10.0.17763",
    "Windows 10 Enterprise Evaluation LTSC 2019 17763": "10.0.17763",
    "Windows 10 Enterprise Evaluation 18362": "10.0.18362",
    "Windows 10 Enterprise Evaluation 18363": "10.0.18363",
    "Windows 10 Enterprise Evaluation 19041": "10.0.19041",
    "Windows Server 2012 Standard 9200": "6.2.9200",
    "Windows Server 2012 R2 Standard 9600": "6.3.9600",
    "Windows Server 2016 Standard 14393": "10.0.14393",
}
