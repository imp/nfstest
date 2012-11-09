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
IPv4 module

Decode IP version 4 layer.
"""
import struct
import nfstest_config as c
from baseobj import BaseObj
from packet.transport.tcp import TCP
from packet.unpack import Unpack

# Module constants
__author__    = 'Jorge Mora (%s)' % c.NFSTEST_AUTHOR_EMAIL
__version__   = '1.0.1'
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"

# Name of different protocols
_IP_map = {1:'ICMP', 2:'IGMP', 6:'TCP', 17:'UDP' }

class TOS(BaseObj): pass
class Flags(BaseObj): pass

class IPv4(BaseObj, Unpack):
    """IPv4 object

       Usage:
           from packet.internet.ipv4 import IPv4

           x = IPv4(pktt, buffer)

       Object definition:

       IPv4(
           version         = int,
           IHL             = int,
           header_size     = int,
           total_size      = int,
           id              = int,
           fragment_offset = int,
           TTL             = int,
           protocol        = int,
           checksum        = int,
           src             = "%d.%d.%d.%d", # source IP address
           dst             = "%d.%d.%d.%d", # destination IP address
           TOS = TOS(
               precedence    = int,
               delay         = int,
               throughput    = int,
               reliability   = int,
               monetary_cost = int,
           ),
           DSCP = int,
           ECN  = int,
           flags = Flags(
               DF = int,
               MF = int,
           )
           options = string, # IP options if available
           data = string,    # Raw data of payload if protocol
                             # is not supported
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
        # Get the IP version and header length
        temp = self.unpack(1, 'B')[0]
        count = 4*(temp & 0x0F)

        # Decode IP header
        ulist = self.unpack(19, 'BHHHBBH4s4s')
        self.version         = (temp >> 4)
        self.IHL             = (temp & 0x0F)
        self.header_size     = count
        self.total_size      = ulist[1]
        self.id              = ulist[2]
        self.fragment_offset = (ulist[3] & 0x1FFF)
        self.TTL             = ulist[4]
        self.protocol        = ulist[5]
        self.checksum        = ulist[6]
        self.src             = "%d.%d.%d.%d" % struct.unpack('!4B', ulist[7])
        self.dst             = "%d.%d.%d.%d" % struct.unpack('!4B', ulist[8])
        self.TOS = TOS(
            precedence    = (ulist[0] >> 5),
            delay         = ((ulist[0] >> 4) & 0x01),
            throughput    = ((ulist[0] >> 3) & 0x01),
            reliability   = ((ulist[0] >> 2) & 0x01),
            monetary_cost = ((ulist[0] >> 1) & 0x01),
        )
        self.DSCP = (ulist[0] >> 2)
        self.ECN  = (ulist[0] & 0x03)
        self.flags = Flags(
            DF = ((ulist[3] >> 14) & 0x01),
            MF = ((ulist[3] >> 13) & 0x01),
        )
        pktt.pkt.ip = self

        if count > 20:
            # Save IP options
            osize = count - 20
            self.options = self.rawdata(osize)

        if self.protocol == 6:
            # Decode TCP
            TCP(pktt, self.data)
            del self.data
        return

    def __str__(self):
        """String representation of object

           The representation depends on the verbose level set by debug_repr().
           If set to 0 the generic object representation is returned.
           If set to 1 the representation of the object is condensed:
               '192.168.0.20 -> 192.168.0.61 '

           If set to 2 the representation of the object also includes the
           protocol and length of payload:
               '192.168.0.20 -> 192.168.0.61, protocol: 17(UDP), len: 84'
        """
        rdebug = self.debug_repr()
        if rdebug == 1:
            out = "%s -> %s " % (self.src, self.dst)
        elif rdebug == 2:
            proto = _IP_map.get(self.protocol, None)
            proto = str(self.protocol) if proto is None else "%d(%s)" % (self.protocol, proto)
            out = "%s -> %s, protocol: %s, len: %d" % (self.src, self.dst, proto, self.total_size)
        else:
            out = BaseObj.__str__(self)
        return out

