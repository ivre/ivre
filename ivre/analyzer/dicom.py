#! /usr/bin/env python

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


import struct
from typing import Dict, Generator, Tuple, Union, cast


from ivre.types.active import NmapPort
from ivre import utils


def _gen_items(data: bytes) -> Generator[Tuple[int, bytes], None, None]:
    while data:
        if len(data) < 4:
            utils.LOGGER.debug(
                "Item too short: maybe a broken DICOM item [%r]",
                data,
            )
            return
        itype, pad, ilen = struct.unpack(">BBH", data[:4])
        if pad != 0:
            utils.LOGGER.debug(
                "Non zero padding: maybe a broken DICOM item [%r]",
                data,
            )
        data = data[4:]
        if ilen < len(data):
            utils.LOGGER.debug(
                "Item too short: maybe a broken DICOM item [%r]",
                data,
            )
        yield (itype, data[:ilen])
        data = data[ilen:]


_USER_INFO_ITEMS = {
    0x51: "max_pdu_length",
    0x52: "implementation_class_uid",
    0x55: "implementation_version",
}


def _parse_items(data: bytes) -> Dict[str, Union[int, str]]:
    res: Dict[str, Union[int, str]] = {}
    items = dict(_gen_items(data))
    if 0x50 not in items:
        utils.LOGGER.warning("No User Info in items [%r]", items)
        return res
    ivalue: bytes
    ivalue_parsed: Union[int, str]
    for itype, ivalue in _gen_items(items[0x50]):
        if itype == 0x51:
            try:
                ivalue_parsed = cast(int, struct.unpack(">I", ivalue)[0])
            except struct.error:
                utils.LOGGER.warning(
                    "Cannot convert max_pdu_length value to an integer [%r]",
                    ivalue,
                )
                ivalue_parsed = utils.encode_b64(ivalue).decode()
        else:
            try:
                ivalue_parsed = ivalue.decode("ascii")
            except struct.error:
                utils.LOGGER.warning(
                    "Cannot convert value to an ASCII string [%r]",
                    ivalue,
                )
                ivalue_parsed = utils.encode_b64(ivalue).decode()
        try:
            itype_parsed = _USER_INFO_ITEMS[itype]
        except KeyError:
            utils.LOGGER.warning(
                "Unknown item type in User Info %02x [%r]", itype, ivalue
            )
            itype_parsed = "unknown_%02x" % itype
        res[itype_parsed] = ivalue_parsed
    return res


def parse_message(data: bytes) -> NmapPort:
    res: NmapPort = {}
    if len(data) < 6:
        utils.LOGGER.debug(
            "Message too short: probably not a DICOM message [%r]",
            data,
        )
        return res
    rtype, pad, rlen = struct.unpack(">BBI", data[:6])
    if pad != 0:
        utils.LOGGER.debug(
            "Non zero padding: probably not a DICOM message [%r]",
            data,
        )
        return res
    if rlen > len(data) - 6:
        utils.LOGGER.debug(
            "Message too short: probably not a DICOM message [%r]",
            data,
        )
        return res
    if rtype in [2, 3]:  # Associate accept / reject
        res["service_name"] = "dicom"
        extra_info: Dict[str, Union[int, str]] = {}
        if rtype == 2:
            msg = "Any AET is accepted (Insecure)"
            if (
                data[6:74]
                != b"\x00\x01\x00\x00ANY-SCP         ECHOSCU         \x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00"
            ):
                extra_info = {"info": "Unusual accept message"}
            else:
                extra_info = _parse_items(data[74:])
        else:
            msg = "Called AET check enabled"
            if data != b"\x03\x00\x00\x00\x00\x04\x00\x01\x01\x07":
                # Result: reject permanent (01)
                # Source: user (01)
                # Reason: called AE title not recognized (07)
                extra_info = {"info": "Unusual reject message"}
        script_output = [
            "",
            "dicom: DICOM Service Provider discovered!",
            "config: %s" % msg,
        ]
        script_data: Dict[str, Union[int, str]] = {
            "dicom": "DICOM Service Provider discovered!",
            "config": msg,
        }
        for key, value in extra_info.items():
            script_output.append("%s: %s" % (key, value))
            script_data[key] = value
        res["scripts"] = [
            {
                "id": "dicom-ping",
                "output": "\n  ".join(script_output),
                "dicom-ping": script_data,
            }
        ]
        return res
    utils.LOGGER.debug(
        "Unknown message type [%r]: probably not a DICOM message [%r]",
        rtype,
        data,
    )
    return res
