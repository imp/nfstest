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
TCP module

Decode TCP layer.
"""
import nfstest_config as c
from baseobj import BaseObj
from packet.application.rpc import RPC

# Module constants
__author__    = 'Jorge Mora (%s)' % c.NFSTEST_AUTHOR_EMAIL
__version__   = '1.0.3'
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"

_TCP_map = {
    0x001:'FIN',
    0x002:'SYN',
    0x004:'RST',
    0x008:'PSH',
    0x010:'ACK',
    0x020:'URG',
    0x040:'ECE',
    0x080:'CWR',
    0x100:'NS',
}

class Flags(BaseObj):
    """Flags object"""
    # Class attributes
    _attrlist = ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", "NS")

    def __init__(self, data):
        """Constructor which takes a short integer as input"""
        self.FIN = (data & 0x01)
        self.SYN = ((data >> 1) & 0x01)
        self.RST = ((data >> 2) & 0x01)
        self.PSH = ((data >> 3) & 0x01)
        self.ACK = ((data >> 4) & 0x01)
        self.URG = ((data >> 5) & 0x01)
        self.ECE = ((data >> 6) & 0x01)
        self.CWR = ((data >> 7) & 0x01)
        self.NS  = ((data >> 8) & 0x01)

class TCP(BaseObj):
    """TCP object

       Usage:
           from packet.transport.tcp import TCP

           x = TCP(pktt)

       Object definition:

       TCP(
           src_port    = int, # Source port
           dst_port    = int, # Destination port
           seq_number  = int, # Sequence number
           ack_number  = int, # Acknowledgment number
           hl          = int, # Data offset or header length (32bit words)
           header_size = int, # Data offset or header length in bytes
           flags_raw   = int, # Raw flags
           flags = Flags(     # Individual flags:
               FIN = int,     #   No more data from sender
               SYN = int,     #   Synchronize sequence numbers
               RST = int,     #   Synchronize sequence numbers
               PSH = int,     #   Push function. Asks to push the buffered
                              #     data to the receiving application
               ACK = int,     #   Acknowledgment field is significant
               URG = int,     #   Urgent pointer field is significant
               ECE = int,     #   ECN-Echo has a dual role:
                              #     SYN=1, the TCP peer is ECN capable.
                              #     SYN=0, packet with Congestion Experienced
                              #     flag in IP header set is received during
                              #     normal transmission
               CWR = int,     #   Congestion Window Reduced
               NS  = int,     #   ECN-nonce concealment protection
           ),
           window_size = int, # Window size
           checksum    = int, # Checksum
           urgent_ptr  = int, # Urgent pointer
           seq         = int, # Relative sequence number
           options = string,  # Raw data of TCP options if available
           data = string,     # Raw data of payload if unable to decode
       )
    """
    # Class attributes
    _attrlist = ("src_port", "dst_port", "seq_number", "ack_number", "hl",
                 "header_size", "flags_raw", "flags", "window_size",
                 "checksum", "urgent_ptr", "options", "data")

    def __init__(self, pktt):
        """Constructor

           Initialize object's private data.

           pktt:
               Packet trace object (packet.pktt.Pktt) so this layer has
               access to the parent layers.
        """
        # Decode the TCP layer header
        unpack = pktt.unpack
        ulist = unpack.unpack(20, "!HHIIHHHH")
        self.src_port    = ulist[0]
        self.dst_port    = ulist[1]
        self.seq_number  = ulist[2]
        self.ack_number  = ulist[3]
        self.hl          = ulist[4] >> 12
        self.header_size = 4*self.hl
        self.flags_raw   = (ulist[4] & 0x1FF)
        self.flags       = Flags(self.flags_raw)
        self.window_size = ulist[5]
        self.checksum    = ulist[6]
        self.urgent_ptr  = ulist[7]

        pktt.pkt.tcp = self

        # Stream identifier
        ip = pktt.pkt.ip
        streamid = "%s:%d-%s:%d" % (ip.src, self.src_port, ip.dst, self.dst_port)

        if streamid not in pktt._tcp_stream_map:
            # msfrag: Keep track of RPC packets spanning multiple TCP packets
            # frag_off: Keep track of multiple RPC packets within
            #           a single TCP packet
            pktt._tcp_stream_map[streamid] = {
                'msfrag':   '',
                'frag_off': 0,
                'last_seq': 0,
                'seq_wrap': 0,
                'seq_base': self.seq_number,
            }

        # De-reference stream map
        stream = pktt._tcp_stream_map[streamid]

        if self.flags.SYN:
            # Reset seq_base on SYN
            stream['seq_base'] = self.seq_number
            stream['last_seq'] = stream['seq_wrap']

        # Convert sequence numbers to relative numbers
        seq = self.seq_number - stream['seq_base'] + stream['seq_wrap']
        if seq < 0:
            # Sequence number has reached the maximum and wrapped around
            stream['seq_wrap'] += 4294967296
            seq += 4294967296
        self.seq = seq

        if self.header_size > 20:
            osize = self.header_size - 20
            self.options = unpack.read(osize)

        # Save length of TCP segment
        self.length = unpack.size()

        if seq < stream['last_seq']:
            # This is a re-transmission, do not process
            return

        self._decode_payload(pktt, stream)

        if self.length > 0:
            stream['last_seq'] = seq

    def __str__(self):
        """String representation of object

           The representation depends on the verbose level set by debug_repr().
           If set to 0 the generic object representation is returned.
           If set to 1 the representation of the object is condensed:
               'TCP 708 -> 2049, seq: 3294175829, ack: 3395739041, ACK,FIN'

           If set to 2 the representation of the object also includes the
           length of payload and a little bit more verbose:
               'src port 708 -> dst port 2049, seq: 3294175829, ack: 3395739041, len: 0, flags: ACK,FIN'
        """
        rdebug = self.debug_repr()
        if rdebug > 0:
            flags = []
            for flag in _TCP_map:
                if self.flags_raw & flag != 0:
                    flags.append(_TCP_map[flag])
        if rdebug == 1:
            out = "TCP %d -> %d, seq: %d, ack: %d, %s" % \
                  (self.src_port, self.dst_port, self.seq_number, self.ack_number, ','.join(flags))
        elif rdebug == 2:
            out = "src port %d -> dst port %d, seq: %d, ack: %d, len: %d, flags: %s" % \
                  (self.src_port, self.dst_port, self.seq_number, self.ack_number, self.length, ','.join(flags))
        else:
            out = BaseObj.__str__(self)
        return out

    def _decode_payload(self, pktt, stream):
        """Decode TCP payload."""
        rpc = None
        pkt = pktt.pkt
        unpack = pktt.unpack
        if stream['frag_off'] > 0 and len(stream['msfrag']) == 0:
            # This RPC packet lies within previous TCP packet,
            # Re-position the offset of the data
            unpack.seek(unpack.tell() + stream['frag_off'])

        # Get the total size
        sid = unpack.save_state()
        size = unpack.size()
        nonvalid = bool(size <= 20 and unpack.getbytes() == '\x00' * size)

        # Try decoding the RPC header before using the msfrag data
        # to re-sync the stream
        if len(stream['msfrag']) > 0:
            rpc = RPC(pktt, proto=6)
            if not rpc:
                unpack.restore_state(sid)
                sid = unpack.save_state()

        if rpc or (size == 0 and len(stream['msfrag']) > 0 and self.flags_raw != 0x10):
            # There has been some data lost in the capture,
            # to continue decoding next packets, reset stream
            # except if this packet is just a TCP ACK (flags = 0x10)
            stream['msfrag'] = ''
            stream['frag_off'] = 0

        # Expected data segment sequence number
        nseg = self.seq - stream['last_seq']

        # Make sure this segment has valid data
        if nseg != len(stream['msfrag']) and nonvalid:
            return

        if not rpc:
            if len(stream['msfrag']):
                # Concatenate previous fragment
                unpack.insert(stream['msfrag'])
            ldata = unpack.size() - 4

            # Get RPC header
            rpc = RPC(pktt, proto=6)
        else:
            ldata = size - 4

        if not rpc:
            return

        rpcsize = rpc.fragment_hdr.size

        truncbytes = pkt.record.length_orig - pkt.record.length_inc
        if truncbytes == 0 and ldata < rpcsize:
            # An RPC fragment is missing to decode RPC payload
            unpack.restore_state(sid)
            stream['msfrag'] += unpack.getbytes()
        else:
            if len(stream['msfrag']) > 0 or ldata == rpcsize:
                stream['frag_off'] = 0
            stream['msfrag'] = ''
            # Save RPC layer on packet object
            pkt.rpc = rpc
            if rpc.type:
                # Remove packet call from the xid map since reply has
                # already been decoded
                pktt._rpc_xid_map.pop(rpc.xid, None)

            # Decode NFS layer
            nfs = rpc.decode_nfs()
            if nfs:
                pkt.nfs = nfs
            rpcbytes = ldata - unpack.size()
            if not nfs and rpcbytes != rpcsize:
                pass
            elif unpack.size():
                # Save the offset of next RPC packet within this TCP packet
                # Data offset is cumulative
                stream['frag_off'] += size - unpack.size()
                sid = unpack.save_state()
                ldata = unpack.size() - 4
                try:
                    rpc_header = RPC(pktt, proto=6, state=False)
                except Exception:
                    rpc_header = None
                if not rpc_header or ldata < rpc_header.fragment_hdr.size:
                    # Part of next RPC packet is within this TCP packet
                    # Save the multi-span fragment data
                    unpack.restore_state(sid)
                    stream['msfrag'] += unpack.getbytes()
                else:
                    # Next RPC packet is entirely within this TCP packet
                    # Re-position the file pointer to the current offset
                    pktt.offset = pktt.boffset
                    pktt._getfh().seek(pktt.offset)
            else:
                stream['frag_off'] = 0
