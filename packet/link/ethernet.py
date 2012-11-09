#===============================================================================
# Copyright 2012 NetApp, Inc. All Rights Reserved,
# contribution by Jorge Mora <mora@netapp.com>
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#===============================================================================
"""
ETHERNET module

Decode ethernet layer (RFC 894) Ethernet II.
"""
import nfstest_config as c
from baseobj import BaseObj
from macaddr import MacAddr
from packet.internet.ipv4 import IPv4
from packet.internet.ipv6 import IPv6
from packet.unpack import Unpack

# Module constants
__author__    = 'Jorge Mora (%s)' % c.NFSTEST_AUTHOR_EMAIL
__version__   = '1.0.1'
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"

_ETHERNET_map = {
    0x0800: 'IPv4',
    0x86dd: 'IPv6',
}

class ETHERNET(BaseObj, Unpack):
    """Ethernet object

       Usage:
           from packet.link.ethernet import ETHERNET

           x = ETHERNET(pktt, buffer)

       Object definition:

       ETHERNET(
           dst   = MacAddr(),  # destination MAC address
           src   = MacAddr(),  # source MAC address
           type  = int,        # payload type
           data  = string,     # raw data of payload if type is not supported
       )
    """
    def __init__(self, pktt, data):
        """Constructor

           Initialize object's private data.

           pktt:
               Packet trace object (packet.pktt.Pktt) so this layer has
               access to the parent layers.
           data:
               Raw packet data for this layer.
        """
        self.data = data
        self.dst  = MacAddr(self.rawdata(6).encode('hex'))
        self.src  = MacAddr(self.rawdata(6).encode('hex'))
        self.type = self.unpack(2, 'H')[0]
        pktt.pkt.ethernet = self

        payload = None
        if self.type == 0x0800:
            # Decode IPv4 packet
            payload = IPv4(pktt, self.data)
        elif self.type == 0x86dd:
            # Decode IPv6 packet
            payload = IPv6(pktt, self.data)
        if payload:
            del self.data
        return

    def __str__(self):
        """String representation of object

           The representation depends on the verbose level set by debug_repr().
           If set to 0 the generic object representation is returned.
           If set to 1 the representation of the object is condensed:
               '00:0c:29:54:09:ef -> 60:33:4b:29:6e:9d '

           If set to 2 the representation of the object also includes the type
           of payload:
               '00:0c:29:54:09:ef -> 60:33:4b:29:6e:9d, type: 0x800(IPv4)'
        """
        rdebug = self.debug_repr()
        if rdebug == 1:
            out = "%s -> %s " % (self.src, self.dst)
        elif rdebug == 2:
            etype = _ETHERNET_map.get(self.type, None)
            etype = hex(self.type) if etype is None else "%s(%s)" % (hex(self.type), etype)
            out = "%s -> %s, type: %s" % (self.src, self.dst, etype)
        else:
            out = BaseObj.__str__(self)
        return out

