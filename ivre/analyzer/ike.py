#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2016 Pierre LALET <pierre.lalet@cea.fr>
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

from scapy.layers.isakmp import ISAKMP, ISAKMP_payload_SA, \
    ISAKMP_payload_VendorID

from ivre.utils import find_ike_vendor_id

def analyze_ike_payload(payload):
    try:
        payload = ISAKMP(payload)
    except:
        return {}
    output = {}
    service = {}
    try:
        isak_trans = payload[ISAKMP_payload_SA].prop.trans
    except (IndexError, AttributeError):
        pass
    else:
        while isak_trans:
            try:
                output.setdefault('transforms', []).append(
                    dict(isak_trans.transforms)
                )
            except (AttributeError, TypeError):
                pass
            isak_trans = isak_trans.payload
    isak_vids = payload
    while True:
        try:
            isak_vids = isak_vids[ISAKMP_payload_VendorID]
        except IndexError:
            break
        name = find_ike_vendor_id(isak_vids.vendorID)
        if name is not None:
            if name.startswith('Windows-'):
                service['service_product'] = "Microsoft/Cisco IPsec"
                service['service_version'] = name.replace('-', ' ')
                service['service_ostype'] = "Windows"
            elif name == 'Windows':
                service['service_product'] = "Microsoft/Cisco IPsec"
                service['service_ostype'] = "Windows"
            elif name.startswith('Firewall-1 '):
                service['service_product'] = 'Checkpoint VPN-1/Firewall-1'
                service['service_version'] = name.split(None, 1)[1]
                service['service_devicetype'] = 'security-misc'
            elif name.startswith('SSH IPSEC Express '):
                service['service_product'] = 'SSH Communications Security IPSec Express'
                service['service_version'] = name.split(None, 3)[3]
            elif name.startswith('SSH Sentinel'):
                service['service_product'] = 'SSH Communications Security Sentinel'
                version = name[13:]
                if version:
                    service['service_version'] = version
            elif name.startswith('SSH QuickSec'):
                service['service_product'] = 'SSH Communications Security QuickSec'
                version = name[13:]
                if version:
                    service['service_version'] = version
            elif name.startswith('Cisco VPN Concentrator'):
                service['service_product'] = 'Cisco VPN Concentrator'
                version = name[24:-1]
                if version:
                    service['service_version'] = version
            elif name.startswith('SafeNet SoftRemote'):
                service['service_product'] = 'SafeNet Remote'
                version = name[19:]
                if version:
                    service['service_version'] = version
            elif name == 'KAME/racoon':
                service['service_product'] = 'KAME/racoon/IPsec Tools'
            elif name == 'Nortel Contivity':
                service['service_product'] = 'Nortel Contivity'
                service['service_devicetype'] = 'firewall'
            elif name.startswith('SonicWall-'):
                service['service_product'] = 'SonicWall'
            elif name.startswith('strongSwan'):
                service['service_product'] = 'strongSwan'
                # for some reason in the fingerprints file, strongSwan ==
                # strongSwan 4.3.6
                service['service_version'] = name[11:] or '4.3.6'
                service['service_ostype'] = 'Unix'
            elif name == 'ZyXEL ZyWall USG 100':
                service['service_product'] = 'ZyXEL ZyWALL USG 100'
                service['service_devicetype'] = 'firewall'
            elif name.startswith('Linux FreeS/WAN '):
                service['service_product'] = 'Linux FreeS/WAN'
                service['service_version'] = name.split(None, 2)[2]
                service['service_ostype'] = 'Unix'
            elif name.startswith('Openswan '):
                service['service_product'] = 'Openswan'
                service['service_version'] = name.split(None, 1)[1]
                service['service_ostype'] = 'Unix'
            elif name == 'FreeS/WAN or OpenSWAN':
                service['service_product'] = 'Linux FreeS/WAN or Openswan'
                service['service_ostype'] = 'Unix'
            elif name.startswith('Libreswan '):
                service['service_product'] = 'Libreswan'
                service['service_version'] = name.split(None, 1)[1]
                service['service_ostype'] = 'Unix'
            elif name == 'OpenPGP':
                service['service_product'] = name
            elif name in ['FortiGate', 'ZyXEL ZyWALL Router',
                          'ZyXEL ZyWALL USG 100']:
                service['service_product'] = name
                service['service_devicetype'] = 'firewall'
            elif name.startswith('Netscreen-'):
                service['service_product'] = 'Juniper'
                service['service_ostype'] = 'NetScreen OS'
                service['service_devicetype'] = 'firewall'
            elif name.startswith('StoneGate-'):
                service['service_product'] = 'StoneGate'
                service['service_devicetype'] = 'firewall'
            elif name.startswith('Symantec-Raptor'):
                service['service_product'] = 'Symantec-Raptor'
                version = name[16:]
                if version:
                    service['service_version'] = version
                service['service_devicetype'] = 'firewall'
            elif name == 'Teldat':
                service['service_product'] = name
                service['service_devicetype'] = 'broadband router'
        if service.get('service_version') == 'Unknown Vsn':
            del service['service_version']
        entry = {'value': isak_vids.vendorID.encode('hex')}
        if name is not None:
            entry["name"] = name
        output.setdefault('vendor_ids', []).append(entry)
        isak_vids = isak_vids.payload
    txtoutput = []
    if 'transforms' in output:
        txtoutput.append('Transforms:')
        for tr in output['transforms']:
            txtoutput.append("  - %s" % ", ".join("%s: %s" % (key, tr[key])
                                                  for key in sorted(tr)))
    if 'vendor_ids' in output:
        txtoutput.append('Vendor IDs:')
        for vid in output['vendor_ids']:
            txtoutput.append("  - %s" % vid.get('name', vid['value']))
    if output:
        # sth identified, let's assume it was correct
        service["service_name"] = "isakmp"
        output = {"scripts": [{"id": "ike-info", "output": "\n".join(txtoutput),
                               "ike-info": output}]} if output else {}
        output.update(service)
    return output
