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
Pkt module

Provides the object for a packet and the string representation of the packet.
This object has an attribute for each of the layers in the packet so each layer
can be accessed directly instead of going through each layer. To access the nfs
layer object you can use 'x.nfs' instead of using 'x.ethernet.ip.tcp.rpc.nfs'
which would very cumbersome to use. Also, since NFS can be used with either
TCP or UDP it would be harder to to access the nfs object independently or
the protocol.

Packet object attributes:
    Pkt(
        record   = Record information (frame number, etc.)
        ethernet = ETHERNET II (RFC 894) object
        ip       = IPv4 object
        tcp      = TCP object
        rpc      = RPC object
        nfs      = NFS object
    )
"""
import nfstest_config as c
from baseobj import BaseObj
from packet.nfs.nfs4_type import COMPOUND4args,COMPOUND4res
from packet.nfs.nfs4_const import nfs_opnum4,nfsstat4

# Module constants
__author__    = 'Jorge Mora (%s)' % c.NFSTEST_AUTHOR_EMAIL
__version__   = '1.0.1'
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"

# The order in which to display all layers in the packet
_PKT_layers = ['record', 'ethernet', 'ip', 'tcp', 'udp', 'rpc', 'nfs']
# Required layers for debug_repr(1)
_PKT_rlayers = ['record', 'ip']
# Packet layers to display as debug_repr(2) for debug_repr(1) if last layer
_PKT_mlayers = ['record', 'ethernet', 'ip']
_maxlen = len(max(_PKT_layers, key=len))

class Pkt(BaseObj):
    """Packet object

       Usage:
           from packet.pkt import Pkt

           x = Pkt()
    """
    def __str__(self):
        """String representation of object

           The representation depends on the verbose level set by debug_repr().
           If set to 0 the generic object representation is returned.
           If set to 1 the representation of is condensed into a single line.
           It contains, the frame number, IP source and destination and/or the
           last layer:
               '1 0.386615 192.168.0.62 -> 192.168.0.17 TCP 2049 -> 708, seq: 3395733180, ack: 3294169773, ACK,SYN'
               '5 0.530957 00:0c:29:54:09:ef -> ff:ff:ff:ff:ff:ff, type: 0x806'
               '19 0.434370 192.168.0.17 -> 192.168.0.62 NFS v4 COMPOUND4 call  SEQUENCE;PUTFH;GETATTR'

           If set to 2 the representation of the object is a line for each layer:
               'Pkt(
                    RECORD:   frame 19 @ 0.434370 secs, 238 bytes on wire, 238 bytes captured
                    ETHERNET: 00:0c:29:54:09:ef -> e4:ce:8f:58:9f:f4, type: 0x800(IPv4)
                    IP:       192.168.0.17 -> 192.168.0.62, protocol: 6(TCP), len: 224
                    TCP:      src port 708 -> dst port 2049, seq: 3294170673, ack: 3395734137, len: 172, flags: ACK,PSH
                    RPC:      CALL(0), program: 100003, version: 4, procedure: 1, xid: 0x1437d3d5
                    NFS:      COMPOUND4args(tag='', minorversion=1, argarray=[nfs_argop4(argop=OP_SEQUENCE, ...), ...])
                )'
        """
        rdebug = self.debug_repr()
        if rdebug > 0:
            out = "Pkt(\n" if rdebug == 2 else ''
            klist = []
            for key in _PKT_layers:
                if hasattr(self, key):
                    klist.append(key)
            lastkey = klist[-1]
            for key in klist:
                value = getattr(self, key, None)
                if value != None and (rdebug > 1 or key == lastkey or key in _PKT_rlayers):
                    if rdebug == 1:
                        if key == 'nfs':
                            out += self._nfs_str(value)
                        else:
                            if key == lastkey and key in _PKT_mlayers:
                                self.debug_repr(2)
                            out += "%s" % str(value)
                            self.debug_repr(rdebug)
                    else:
                        sps = " " * (_maxlen - len(key))
                        out += "    %s:%s %s\n" % (key.upper(), sps, str(value))
            out += ")\n" if rdebug == 2 else ""
        else:
            out = BaseObj.__str__(self)
        return out

    def _nfs_str(self, nfs):
        """Internal method to return a condensed string representation
           of the NFS packet.
        """
        out = 'NFS v%d ' % self.rpc.version
        if isinstance(nfs, COMPOUND4args):
            out += 'COMPOUND4 call  '
            oplist = []
            for item in nfs.argarray:
                oplist.append(nfs_opnum4[item.argop][3:])
            out += ';'.join(oplist)
        elif isinstance(nfs, COMPOUND4res):
            out += 'COMPOUND4 reply '
            oplist = []
            for item in nfs.resarray:
                oplist.append(nfs_opnum4[item.resop][3:])
            out += ';'.join(oplist)
            if nfs.status != 0:
                out += ' -> ' + nfsstat4[nfs.status]
        return out

