# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
This protocol is based on
    Virtual eXtensible Local Area Network (VXLAN)
    - RFC 7348 -

    This is a custom protocol designed for Alibaba,
    unlike a standard VXLAN, the next protocol is
    always IPv4

A Framework for Overlaying Virtualized Layer 2 Networks over Layer 3 Networks
http://tools.ietf.org/html/rfc7348
https://www.ietf.org/id/draft-ietf-nvo3-vxlan-gpe-02.txt

VXLAN Group Policy Option:
http://tools.ietf.org/html/draft-smith-vxlan-group-policy-00
"""

from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP, UDP
from scapy.fields import FlagsField, XByteField, ThreeBytesField, \
    ConditionalField, ShortField, ByteEnumField, X3BytesField

_GP_FLAGS = ["R", "R", "R", "A", "R", "R", "D", "R"]


class L3VXLAN(Packet):
    name = "L3VXLAN"

    fields_desc = [
        FlagsField("flags", 0x8, 8,
                   ['OAM', 'R', 'NextProtocol', 'Instance',
                    'V1', 'V2', 'R', 'G']),
        ConditionalField(
            ShortField("reserved0", 0),
            lambda pkt: pkt.flags.NextProtocol,
        ),
        ConditionalField(
            ByteEnumField('NextProtocol', 0,
                          {0: 'NotDefined',
                           1: 'IPv4',
                           2: 'IPv6',
                           3: 'Ethernet',
                           4: 'NSH'}),
            lambda pkt: pkt.flags.NextProtocol,
        ),
        ConditionalField(
            ThreeBytesField("reserved1", 0),
            lambda pkt: (not pkt.flags.G) and (not pkt.flags.NextProtocol),
        ),
        ConditionalField(
            FlagsField("gpflags", 0, 8, _GP_FLAGS),
            lambda pkt: pkt.flags.G,
        ),
        ConditionalField(
            ShortField("gpid", 0),
            lambda pkt: pkt.flags.G,
        ),
        X3BytesField("vni", 0),
        XByteField("reserved2", 0),
    ]

    # Use default linux implementation port
    overload_fields = {
        UDP: {'dport': 250},
    }

    def mysummary(self):
        if self.flags.G:
            return self.sprintf("L3VXLAN (vni=%L3VXLAN.vni% gpid=%L3VXLAN.gpid%)")
        else:
            return self.sprintf("L3VXLAN (vni=%L3VXLAN.vni%)")


bind_layers(UDP, L3VXLAN, dport=250)
bind_layers(UDP, L3VXLAN, sport=4789, dport=250)

bind_layers(L3VXLAN, IP)
