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
from packet.unpack import Unpack

# Module constants
__author__    = 'Jorge Mora (%s)' % c.NFSTEST_AUTHOR_EMAIL
__version__   = '1.0.1'
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"

_TCP_map = {
    0x01:'FIN',
    0x02:'SYN',
    0x04:'RST',
    0x08:'PSH',
    0x10:'ACK',
    0x20:'URG',
    0x40:'ECE',
    0x80:'CWR',
}

class Flags(BaseObj): pass

class TCP(BaseObj, Unpack):
    """TCP object

       Usage:
           from packet.transport.tcp import TCP

           x = TCP(pktt, buffer)

       Object definition:

       TCP(
           src_port    = int,
           dst_port    = int,
           seq_number  = int,
           seq         = int, # relative sequence number
           ack_number  = int,
           hl          = int,
           header_size = int,
           window_size = int,
           checksum    = int,
           urgent_ptr  = int,
           flags_raw   = int, # raw flags
           flags = Flags(
               FIN = int,
               SYN = int,
               RST = int,
               PSH = int,
               ACK = int,
               URG = int,
               ECE = int,
               CWR = int,
           ),
           options = string, # raw data of TCP options if available
           data = string,    # raw data of payload if unable to decode
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
        # Decode the TCP layer header
        ulist = self.unpack(20, 'HHIIBBHHH')
        temp = ulist[4] >> 4
        count = 4*temp
        self.src_port    = ulist[0]
        self.dst_port    = ulist[1]
        self.seq_number  = ulist[2]
        self.ack_number  = ulist[3]
        self.hl          = temp
        self.header_size = count
        self.window_size = ulist[6]
        self.checksum    = ulist[7]
        self.urgent_ptr  = ulist[8]
        self.flags_raw   = (ulist[5] & 0xFF)
        self.flags = Flags(
            FIN = (ulist[5] & 0x01),
            SYN = ((ulist[5] >> 1) & 0x01),
            RST = ((ulist[5] >> 2) & 0x01),
            PSH = ((ulist[5] >> 3) & 0x01),
            ACK = ((ulist[5] >> 4) & 0x01),
            URG = ((ulist[5] >> 5) & 0x01),
            ECE = ((ulist[5] >> 6) & 0x01),
            CWR = ((ulist[5] >> 7) & 0x01),
        )
        pktt.pkt.tcp = self

        # Stream identifier
        streamid = self._streamid(pktt.pkt)

        if not getattr(pktt, '_tcp_stream_map', None):
            # TCP stream map: to keep track of the different TCP streams
            # within the trace file -- used to deal with RPC packets spanning
            # multiple TCP packets or to handle a TCP packet having multiple
            # RPC packets
            pktt._tcp_stream_map = {}

        if streamid not in pktt._tcp_stream_map:
            # msfrag: Keep track of RPC packets spanning multiple TCP packets
            # frag_off: Keep track of multiple RPC packets within
            #           a single TCP packet
            pktt._tcp_stream_map[streamid] = {
                'seq_base': self.seq_number,
                'smap':     {},
                'pindex':   pktt.index,
                'msfrag':   '',
                'frag_off': 0,
                'last_seq': 0,
            }

        # De-reference stream map
        stream = pktt._tcp_stream_map[streamid]

        # Convert sequence numbers to relative numbers
        seq = self.seq_number - stream['seq_base']
        self.seq = seq

        if count > 20:
            osize = count - 20
            self.options = self.rawdata(osize)

        # Save length of TCP segment
        self.length = len(self.data)

        if seq < stream['last_seq']:
            # This is a re-transmission, do not process
            return

        # Save data
        save_data = self.data

        # Expected data segment sequence number
        nseg = self.seq - stream['last_seq']

        # Make sure this segment has valid data
        if nseg != len(stream['msfrag']) and \
           len(self.data) <= 20 and self.data == '\x00' * len(self.data):
            save_data = ""

        # Append segment to the stream map
        if pktt.index == pktt.mindex:
            smap = stream['smap']
            if len(stream['msfrag']) == 0 and stream['frag_off'] == 0:
                stream['pindex'] = pktt.index
            else:
                smap_item = [stream['pindex'], stream['frag_off']]
                smap[pktt.index] = smap_item

        self._decode_payload(pktt, stream)

        if getattr(pktt.pkt, 'rpc', None) or len(save_data) == 0:
            stream['pindex'] = pktt.index

        if self.length > 0:
            stream['last_seq'] = seq
        return

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
        if stream['frag_off'] > 0 and len(stream['msfrag']) == 0:
            # This RPC packet lies within previous TCP packet,
            # Re-position the offset of the data
            self.data = self.data[stream['frag_off']:]

        # Get the total size
        save_data = self.data
        size = len(self.data)

        # Try decoding the RPC header before using the msfrag data
        # to re-sync the stream
        if len(stream['msfrag']) > 0:
            rpc = RPC(pktt, self.data, proto=6)
            if not rpc:
                self.data = save_data

        if rpc or (size == 0 and len(stream['msfrag']) > 0 and self.flags_raw != 0x10):
            # There has been some data lost in the capture,
            # to continue decoding next packets, reset stream
            # except if this packet is just a TCP ACK (flags = 0x10)
            stream['msfrag'] = ''
            stream['frag_off'] = 0

        # Expected data segment sequence number
        nseg = self.seq - stream['last_seq']

        # Make sure this segment has valid data
        if nseg != len(stream['msfrag']) and \
           size <= 20 and save_data == '\x00' * size:
            return

        if not rpc:
            # Concatenate previous fragment
            self.data = stream['msfrag'] + self.data
            ldata = len(self.data) - 4

            # Get RPC header
            rpc = RPC(pktt, self.data, proto=6)
        else:
            ldata = size - 4

        if not rpc:
            return

        rpcsize = rpc.fragment_hdr.size

        if ldata < rpcsize:
            # An RPC fragment is missing to decode RPC payload
            stream['msfrag'] += save_data
        else:
            if len(stream['msfrag']) > 0 or ldata == rpcsize:
                stream['frag_off'] = 0
            stream['msfrag'] = ''
            # Save RPC layer on packet object
            pktt.pkt.rpc = rpc
            del self.data

            # Decode NFS layer
            nfs = rpc.decode_nfs()
            if nfs:
                pktt.pkt.nfs = nfs
            rpcbytes = ldata - len(rpc.data)
            if not nfs and rpcbytes != rpcsize:
                pass
            elif rpc.data:
                # Save the offset of next RPC packet within this TCP packet
                # Data offset is cumulative
                stream['frag_off'] += size - len(rpc.data)
                save_data = rpc.data
                ldata = len(rpc.data) - 4
                try:
                    rpc_header = RPC(pktt, rpc.data, proto=6)
                except Exception:
                    rpc_header = None
                if not rpc_header or ldata < rpc_header.fragment_hdr.size:
                    # Part of next RPC packet is within this TCP packet
                    # Save the multi-span fragment data
                    stream['msfrag'] += save_data
                else:
                    # Next RPC packet is entirely within this TCP packet
                    # Re-position the file pointer to the current offset
                    pktt.offset = pktt.b_offset
                    pktt._getfh().seek(pktt.offset)
            else:
                stream['frag_off'] = 0

    def _streamid(self, pkt):
        """Get TCP streamid."""
        streamid = "%s:%d-%s:%d" % (pkt.ip.src,
                                    pkt.tcp.src_port,
                                    pkt.ip.dst,
                                    pkt.tcp.dst_port)
        return streamid

