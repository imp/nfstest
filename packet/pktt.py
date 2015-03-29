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
Packet trace module

The Packet trace module is a python module that takes a trace file created
by tcpdump and unpacks the contents of each packet. You can decode one packet
at a time, or do a search for specific packets. The main difference between
this modules and other tools used to decode trace files is that you can use
this module to completely automate your tests.

How does it work? It opens the trace file and reads one record at a time
keeping track where each record starts. This way, very large trace files
can be opened without having to wait for the file to load and avoid loading
the whole file into memory.

Packet layers supported:
    - ETHERNET II (RFC 894)
    - IP layer (supports IPv4 and IPv6)
    - TCP layer
    - RPC layer
    - NFS v4.0
    - NFS v4.1 including pNFS file layouts
"""
import os
import re
import gzip
import time
import token
import struct
import parser
import symbol
import nfstest_config as c
from baseobj import BaseObj
from packet.pkt import Pkt
from packet.unpack import Unpack
from packet.record import Record
from packet.link.ethernet import ETHERNET

# Module constants
__author__    = 'Jorge Mora (%s)' % c.NFSTEST_AUTHOR_EMAIL
__version__   = '1.0.2'
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"

BaseObj.debug_map(0x100000000, 'pkt1', "PKT1: ")
BaseObj.debug_map(0x200000000, 'pkt2', "PKT2: ")
BaseObj.debug_map(0x400000000, 'pkt3', "PKT3: ")
BaseObj.debug_map(0x800000000, 'pkt4', "PKT4: ")
BaseObj.debug_map(0xF00000000, 'pktt', "PKTT: ")

# Map of tokens
_token_map = dict(token.tok_name.items() + symbol.sym_name.items())
# Map of items not in the array of the compound
_nfsopmap = {'status': 1, 'tag': 1}
# Match function map
_match_func_map = {
    'ETHERNET': 'self.match_ethernet',
    'IP':       'self.match_ip',
    'TCP':      'self.match_tcp',
    'RPC':      'self.match_rpc',
    'NFS':      'self.match_nfs',
}

class Header(BaseObj): pass

class Pktt(BaseObj, Unpack):
    """Packet trace object

       Usage:
           from packet.pktt import Pktt

           x = Pktt("/traces/tracefile.cap")

           # Iterate over all packets found in the trace file
           for pkt in x:
               print pkt
    """
    def __init__(self, tfile, live=False, state=True):
        """Constructor

           Initialize object's private data, note that this will not check the
           file for existence nor will open the file to verify if it is a valid
           tcpdump file. The tcpdump trace file will be opened the first time a
           packet is retrieved.

           tracefile:
               Name of tcpdump trace file (little or big endian format)
           live:
               If set to True, methods will not return if encountered <EOF>,
               they will keep on trying until more data is available in the
               file. This is useful when running tcpdump in parallel,
               especially when tcpdump is run with the '-C' option, in which
               case when <EOF> is encountered the next trace file created by
               tcpdump will be opened and the object will be re-initialized,
               all private data referencing the previous file is lost.
        """
        self.tfile   = tfile  # Current trace file name
        self.bfile   = tfile  # Base trace file name
        self.live    = live   # Set to True if dealing with a live tcpdump file
        self.state   = state  # Set to False so state is not kept,
                              # use for large trace files to save some memory
        self.offset  = 0      # Current file offset
        self.index   = 0      # Current packet index
        self.mindex  = 0      # Maximum packet index processed so far
        self.findex  = 0      # Current tcpdump file index (used with self.live)
        self.fh      = None   # Current file handle
        self.pkt     = None   # Current packet
        self.pkt_map = []     # Packet map: pkt_map[self.index] = self.offset

        # TCP stream map: to keep track of the different TCP streams within
        # the trace file -- used to deal with RPC packets spanning multiple
        # TCP packets or to handle a TCP packet having multiple RPC packets
        self._tcp_stream_map = {}

    def __del__(self):
        """Destructor

           Gracefully close the tcpdump trace file if it is opened.
        """
        if self.fh:
            self.fh.close()

    def __iter__(self):
        """Make this object iterable."""
        return self

    def __contains__(self, expr):
        """Implement membership test operator.
           Return true if expr matches a packet in the trace file,
           false otherwise.

           The packet is also stored in the object attribute pkt.

           Examples:
               # Find the next READ request
               if ("NFS.argop == 25" in x):
                   print x.pkt.nfs

           See match() method for more information
        """
        pkt = self.match(expr)
        return (pkt is not None)

    def __getitem__(self, index):
        """Get the packet from the trace file given by the index
           or raise IndexError.

           The packet is also stored in the object attribute pkt.

           Examples:
               pkt = x[index]
        """
        self.dprint('PKT4', ">>> __getitem__(%d)" % index)
        if index < 0:
            # No negative index is allowed
            raise IndexError

        try:
            if index == self.pkt.record.index:
                # The requested packet is in memory, just return it
                return self.pkt
        except:
            pass

        if index < self.index and index < len(self.pkt_map):
            # Reset the current packet index and offset
            # The index is less than the current packet offset so position
            # the file pointer to the offset of the packet given by index
            self.rewind(index)

        # Move to the packet specified by the index
        pkt = None
        while self.index <= index:
            try:
                pkt = self.next()
            except:
                break

        if pkt is None:
            raise IndexError
        return pkt

    def next(self):
        """Get the next packet from the trace file or raise StopIteration.

           The packet is also stored in the object attribute pkt.

           Examples:
               # Iterate over all packets found in the trace file using
               # the iterable properties of the object
               for pkt in x:
                   print pkt

               # Iterate over all packets found in the trace file using it
               # as a method and using the object variable as the packet
               # Must use the try statement to catch StopIteration exception
               try:
                   while (x.next()):
                       print x.pkt
               except StopIteration:
                   pass

               # Iterate over all packets found in the trace file using it
               # as a method and using the return value as the packet
               # Must use the try statement to catch StopIteration exception
               while True:
                   try:
                       print x.next()
                   except StopIteration:
                       break

           NOTE:
               Supports only single active iteration
        """
        self.dprint('PKT4', ">>> %d: next()" % self.index)
        # Initialize next packet
        self.pkt = Pkt()

        # Save file offset for this packet
        self.b_offset = self.offset
        if self.state and self.index >= len(self.pkt_map):
            self.pkt_map.append(self.offset)

        # Get record header
        rec_keys = ('seconds', 'usecs', 'length_inc', 'length_orig')
        header = self._read(16)
        if len(header) < 16:
            raise StopIteration
        self.pkt.record = Record(rec_keys, struct.unpack(self.header_rec, header))
        secs = float(self.pkt.record.seconds) + float(self.pkt.record.usecs)/1000000.0
        if self.tstart is None:
            self.tstart = secs
        self.pkt.record.secs = secs - self.tstart

        # Get the data
        self.data = self._read(self.pkt.record.length_inc)
        if len(self.data) < self.pkt.record.length_inc:
            raise StopIteration

        if self.header.link_type == 1:
            # Decode ethernet layer
            ETHERNET(self)
        else:
            # Unknown link layer
            self.pkt.record.data = self.data

        # Save record index
        self.pkt.record.index = self.index

        # Increment packet index
        self.index += 1
        if self.index > self.mindex:
            self.mindex = self.index

        return self.pkt

    def rewind(self, index=0):
        """Rewind the trace file by setting the file pointer to the start of
           the given packet index. Returns False if unable to rewind the file,
           e.g., when the given index is greater than the maximum number
           of packets processed so far.
        """
        self.dprint('PKT1', ">>> rewind(%d)" % index)
        if index >= 0 and index < len(self.pkt_map):
            # Reset the current packet index and offset to the first packet
            self.offset = self.pkt_map[0]
            self.index = 0

            # Position the file pointer to the offset of the first packet
            self._getfh().seek(self.offset)

            # Clear stream fragments
            for stream_key in self._tcp_stream_map:
                stream = self._tcp_stream_map[stream_key]
                stream['last_seq'] = 0
                stream['frag_off'] = 0
                stream['msfrag'] = ''

            # Move to the packet before the specified by the index so the
            # next packet fetched will be the one given by index
            while self.index < index:
                try:
                    pkt = self.next()
                except:
                    break

            return True
        return False

    def _getfh(self):
        """Get the filehandle of the trace file, open file if necessary."""
        if self.fh == None:
            # Check size of file
            fstat = os.stat(self.tfile)
            if fstat.st_size == 0:
                raise Exception("Packet trace file is empty")

            # Open trace file
            self.fh = open(self.tfile, 'rb')

            iszip = False
            self.header_fmt = None
            while self.header_fmt is None:
                # Initialize offset
                self.offset = 0

                # Get file identifier
                try:
                    self.ident = self._read(4)
                except:
                    self.ident = ""

                if self.ident == '\324\303\262\241':
                    # Little endian
                    self.header_fmt = '<HHIIII'
                    self.header_rec = '<IIII'
                elif self.ident == '\241\262\303\324':
                    # Big endian
                    self.header_fmt = '>HHIIII'
                    self.header_rec = '>IIII'
                else:
                    if iszip:
                        raise Exception('Not a tcpdump file')
                    iszip = True
                    self.fh.seek(0)
                    # Try if this is a gzip compress file
                    self.fh = gzip.GzipFile(fileobj=self.fh)

            # Get header information
            head_keys = ('major', 'minor', 'zone_offset', 'accuracy', 'dump_length', 'link_type')
            self.header = Header(head_keys, struct.unpack(self.header_fmt, self._read(20)))

            # Initialize packet number
            self.index = 0
            self.pkt_map = [self.offset]
            self.tstart = None

        return self.fh

    def _read(self, count):
        """Wrapper for read in order to increment the object's offset. It also
           takes care of <EOF> when 'live' option is set which keeps on trying
           to read and switching files when needed.
        """
        while True:
            # Read number of bytes specified
            data = self._getfh().read(count)
            ldata = len(data)
            if self.live and ldata != count:
                # Not all data was read (<EOF>)
                tracefile = "%s%d" % (self.bfile, self.findex+1)
                # Check if next trace file exists
                if os.path.isfile(tracefile):
                    # Save information that keeps track of the next trace file
                    basefile = self.bfile
                    findex = self.findex + 1
                    # Re-initialize the object
                    self.__del__()
                    self.__init__(tracefile, live=self.live)
                    # Overwrite next trace file info
                    self.bfile = basefile
                    self.findex = findex
                # Re-position file pointer to last known offset
                self._getfh().seek(self.offset)
                time.sleep(1)
            else:
                break

        # Increment object's offset by the amount of data read
        self.offset += ldata
        return data

    def _split_match(self, args):
        """Split match arguments and return a tuple (lhs, opr, rhs)
           where lhs is the left hand side of the given argument expression,
           opr is the operation and rhs is the right hand side of the given
           argument expression:

               <lhs> <opr> <rhs>

           Valid opr values are: ==, !=, <, >, <=, >=, in
        """
        m = re.search(r"([^!=<>]+)\s*([!=<>]+|in)\s*(.*)", args)
        lhs = m.group(1).rstrip()
        opr = m.group(2)
        rhs = m.group(3)
        return (lhs, opr, rhs)

    def _process_match(self, obj, lhs, opr, rhs):
        """Process "regex" and 'in' operator on match expression.
           Regular expression is given as re('regex') and converted to a
           proper regex re.search('regex', data), where data is the object
           compose of obj and lhs|rhs depending on opr. The argument obj
           is an object prefix.

           If opr is a comparison operation (==, !=, etc.), both obj and lhs
           will be the actual LHS and rhs will be the actual RHS.
           If opr is 'in', lhs will be the actual LHS and both obj and rhs
           will be the actual RHS.

           Return the processed match expression.

           Examples:
               # Regular expression processing
               expr = x._process_match('self.pkt.ip.', 'src', '==', "re(r'192\.*')")

               Returns the following expression ready to be evaluated:
               expr = "re.search(r'192\.*', str(self.pkt,ip.src))"

               # Object prefix processing
               expr = x._process_match('item.', 'argop', '==', '25')

               Returns the following expression ready to be evaluated:
               expr = "item.argop==25"

               # Membership (in) processing
               expr = x._process_match('item.', '62', 'in', 'obj_attributes')

               Returns the following expression ready to be evaluated:
               expr = "62 in item.obj_attributes"
        """
        if rhs[:3] == 're(':
            # Regular expression, it must be in rhs
            rhs = "re.search" + rhs[2:]
            if opr == "!=":
                rhs = "not " + rhs
            expr = rhs[:-1] + ", str(" + obj + lhs +  "))"
        elif opr == 'in':
            if self.inlhs:
                expr = obj + lhs + ' ' + opr + ' ' + rhs
            else:
                expr = lhs + ' ' + opr + ' ' + obj + rhs
        else:
            expr = obj + lhs + opr + rhs

        return expr

    def _match(self, layer, args):
        """Default match function."""
        obj = "self.pkt.%s." % layer.lower()
        lhs, opr, rhs = self._split_match(args)
        expr = self._process_match(obj, lhs, opr, rhs)
        texpr = eval(expr)
        self.dprint('PKT2', "    %d: match_%s(%s) -> %r" % (self.pkt.record.index, layer, args, texpr))
        return texpr

    def match_ethernet(self, args):
        """Match ETHERNET values on current packet.

           See ETHERNET() object for more information
        """
        return self._match('ethernet', args)

    def match_ip(self, args):
        """Match IP values on current packet.

           See IPv4() and IPv6() object for more information
        """
        return self._match('ip', args)

    def match_tcp(self, args):
        """Match TCP values on current packet.

           See TCP() object for more information
        """
        return self._match('tcp', args)

    def match_rpc(self, args):
        """Match RPC values on current packet.

           See RPC() object for more information
        """
        return self._match('rpc', args)

    def _match_nfs(self, args):
        """Match NFS values on current packet."""
        array = None
        isarg = True
        lhs, opr, rhs = self._split_match(args)

        if _nfsopmap.get(lhs):
            try:
                # Top level NFS packet info
                expr = self._process_match("self.pkt.nfs.", lhs, opr, rhs)
                return eval(expr)
            except Exception:
                return False

        try:
            array = self.pkt.nfs.argarray
        except Exception:
            try:
                array  = self.pkt.nfs.resarray
                isarg = False
            except Exception:
                # No NFS or no compound call/reply
                return False

        idx = 0
        for item in array:
            try:
                if isarg:
                    op  = "item.arg"
                else:
                    op  = "item.res"

                if lhs == 'op':
                    obj_prefix = op
                else:
                    obj_prefix = "item."

                # Get expression to eval
                expr = self._process_match(obj_prefix, lhs, opr, rhs)
                if eval(expr):
                    self.pkt.NFSop = item
                    self.pkt.NFSidx = idx
                    return True
            except Exception:
                # Continue searching
                pass
            idx += 1
        return False

    def match_nfs(self, args):
        """Match NFS values on current packet.

           In NFSv4, there is a single compound procedure with multiple
           operations, matching becomes a little bit tricky in order to make
           the matching expression easy to use. The NFS object's name space
           gets converted into a flat name space for the sole purpose of
           matching. In other words, all operation objects in argarray or
           resarray are treated as being part of the NFS object's top level
           attributes.

           Consider the following NFS object:
               nfsobj = COMPOUND4res(
                   status=NFS4_OK,
                   tag='NFSv4_tag',
                   resarray=[
                       nfs_resop4(
                           resop=OP_SEQUENCE,
                           opsequence=SEQUENCE4res(
                               sr_status=NFS4_OK,
                               sr_resok4=SEQUENCE4resok(
                                   sr_sessionid='sessionid',
                                   sr_sequenceid=25,
                                   sr_slotid=0,
                                   sr_highest_slotid=0,
                                   sr_target_highest_slotid=15,
                                   sr_status_flags=0,
                               )
                           )
                       ),
                       nfs_resop4(
                           resop=OP_PUTFH,
                           opputfh=PUTFH4res(
                               status=NFS4_OK
                           )
                       ),
                       ...
                   ]
               ),

           The result for operation PUTFH is the second in the list:
               putfh = nfsobj.resarray[1]

           From this putfh object the status operation can be accessed as:
               status = putfh.opputfh.status

           or simply as (this is how the NFS object works):
               status = putfh.status

           In this example, the following match expression 'NFS.status == 0'
           could match the top level status of the compound (nfsobj.status)
           or the putfh status (nfsobj.resarray[1].status)

           The following match expression 'NFS.sr_sequenceid == 25' will also
           match this packet as well, even though the actual expression should
           be 'nfsobj.resarray[0].opsequence.sr_resok4.sr_sequenceid == 25' or
           simply 'nfsobj.resarray[0].sr_sequenceid == 25'.

           This approach makes the match expressions simpler at the expense of
           having some ambiguities on where the actual matched occurred. If a
           match is desired on a specific operation, a more qualified name can
           be given. In the above example, in order to match the status of the
           PUTFH operation the match expression 'NFS.opputfh.status == 0' can
           be used. On the other hand, consider a compound having multiple
           PUTFH results the above match expression will always match the first
           occurrence of PUTFH where the status is 0. There is no way to tell
           the match engine to match the second or Nth occurrence of an
           operation.
        """
        texpr = self._match_nfs(args)
        self.dprint('PKT2', "    %d: match_nfs(%s) -> %r" % (self.pkt.record.index, args, texpr))
        return texpr

    def _convert_match(self, ast):
        """Convert a parser list match expression into their corresponding
           function calls.

           Example:
               expr = "TCP.flags.ACK == 1 and NFS.argop == 50"
               st = parser.expr(expr)
               ast = parser.st2list(st)
               data =  self._convert_match(ast)

               Returns:
               data = "(self.match_tcp('flags.ACK==1'))and(self.match_nfs('argop==50'))"
        """
        ret = ''
        isin = False
        if not isinstance(ast, list):
            if ast in _match_func_map:
                # Replace name by its corresponding function name
                return _match_func_map[ast]
            return ast
        if len(ast) == 2:
            return self._convert_match(ast[1])

        for a in ast[1:]:
            data = self._convert_match(a)
            if data == 'in':
                data = ' in '
                isin = True
                if ret[:5] == "self.":
                    # LHS in the 'in' operator is a packet object
                    self.inlhs = True
                else:
                    # LHS in the 'in' operator is a constant value
                    self.inlhs = False
            ret += data

        if _token_map[ast[0]] == "comparison":
            # Comparison
            if isin:
                m = re.search(r'(.*)(self\.match_\w+)\.(.*)', ret)
                func = m.group(2)
                args = m.group(1) + m.group(3)
            else:
                m = re.search(r"^(self\.match_\w+)\.(.*)", ret)
                func = m.group(1)
                args = m.group(2)
            # Escape all single quotes since the whole string will be quoted
            args = re.sub(r"'", "\\'", args)
            ret = "(%s('%s'))" % (func, args)

        return ret

    def match(self, expr, maxindex=None):
        """Return the packet that matches the given expression, also the packet
           index points to the next packet after the matched packet.
           Returns None if packet is not found and the packet index points
           to the packet at the beginning of the search.

           expr:
               String of expressions to be evaluated
           maxindex:
               The match fails if packet index hits this limit

           Examples:
               # Find the packet with both the ACK and SYN TCP flags set to 1
               pkt = x.match("TCP.flags.ACK == 1 and TCP.flags.SYN == 1")

               # Find the next NFS EXCHANGE_ID request
               pkt = x.match("NFS.argop == 42")

               # Find the next NFS EXCHANGE_ID or CREATE_SESSION request
               pkt = x.match("NFS.argop in [42,43]")

               # Find the next NFS OPEN request or reply
               pkt = x.match("NFS.op == 18")

               # Find all packets coming from subnet 192.168.1.0/24 using
               # a regular expression
               while x.match(r"IP.src == re('192\.168\.1\.\d*')"):
                   print x.pkt.tcp

               # Find packet having a GETATTR asking for FATTR4_FS_LAYOUT_TYPE(bit 62)
               pkt_call = x.match("NFS.attr_request & 0x4000000000000000L != 0")
               if pkt_call:
                   # Find GETATTR reply
                   xid = pkt_call.rpc.xid
                   # Find reply where the number 62 is in the array NFS.obj_attributes
                   pkt_reply = x.match("RPC.xid == %d and 62 in NFS.obj_attributes" % xid)

               # Find the next WRITE request
               pkt = x.match("NFS.argop == 38")
               if pkt:
                   print pkt.nfs

               # Same as above, but using membership test operator instead
               if ("NFS.argop == 38" in x):
                   print x.pkt.nfs

           See also:
               match_ethernet(), match_ip(), match_tcp(), match_rpc(), match_nfs()
        """
        # Save current position
        save_index = self.index

        # Parse match expression
        st = parser.expr(expr)
        smap = parser.st2list(st)
        pdata = self._convert_match(smap)
        self.dprint('PKT1', ">>> %d: match(%s)" % (self.index, expr))

        # Search one packet at a time
        for pkt in self:
            if maxindex and self.index > maxindex:
                # Hit maxindex limit
                break
            try:
                if eval(pdata):
                    # Return matched packet
                    self.dprint('PKT1', ">>> %d: match() -> True" % pkt.record.index)
                    return pkt
            except Exception:
                pass

        # No packet matched, re-position the file pointer back to where
        # the search started
        self.rewind(save_index)
        self.pkt = None
        self.dprint('PKT1', ">>> match() -> False")
        return None

    @staticmethod
    def escape(data):
        """Escape special characters.

           Examples:
               # Call as an instance
               escaped_data = x.escape(data)

               # Call as a class
               escaped_data = Pktt.escape(data)
        """
        # repr() can escape or not a single quote depending if a double
        # quote is present, just make sure both quotes are escaped correctly
        rdata = repr(data)
        if rdata[0] == '"':
            # Double quotes are escaped
            dquote = r'x22'
            squote = r'\x27'
        else:
            # Single quotes are escaped
            dquote = r'\x22'
            squote = r'x27'
        # Replace all double quotes to its corresponding hex value
        data = re.sub(r'"', dquote, rdata[1:-1])
        # Replace all single quotes to its corresponding hex value
        data = re.sub(r"'", squote, data)
        # Escape all backslashes
        data = re.sub(r'\\', r'\\\\', data)
        return data

    @staticmethod
    def ip_tcp_src_expr(ipaddr, port):
        """Return a match expression to find a packet coming from ipaddr:port.

           Examples:
               # Call as an instance
               expr = x.ip_tcp_src_expr('192.168.1.50', 2049)

               # Call as a class
               expr = Pktt.ip_tcp_src_expr('192.168.1.50', 2049)

               # Returns "IP.src == '192.168.1.50' and TCP.src_port == 2049"
               # Expression ready for x.match()
               pkt = x.match(expr)
        """
        return "IP.src == '%s' and TCP.src_port == %d" % (ipaddr, port)

    @staticmethod
    def ip_tcp_dst_expr(ipaddr, port):
        """Return a match expression to find a packet going to ipaddr:port.

           Examples:
               # Call as an instance
               expr = x.ip_tcp_dst_expr('192.168.1.50', 2049)

               # Call as a class
               expr = Pktt.ip_tcp_dst_expr('192.168.1.50', 2049)

               # Returns "IP.dst == '192.168.1.50' and TCP.dst_port == 2049"
               # Expression ready for x.match()
               pkt = x.match(expr)
        """
        return "IP.dst == '%s' and TCP.dst_port == %d" % (ipaddr, port)

if __name__ == '__main__':
    # Self test of module
    l_escape = [
        "hello",
        "\x00\\test",
        "single'quote",
        'double"quote',
        'back`quote',
        'single\'double"quote',
        'double"single\'quote',
        'single\'double"back`quote',
        'double"single\'back`quote',
    ]
    ntests = 2*len(l_escape)

    tcount = 0
    for quote in ["'", '"']:
        for data in l_escape:
            expr = "data == %s%s%s" % (quote, Pktt.escape(data), quote)
            expr = re.sub(r'\\\\', r'\\', expr)
            if eval(expr):
                tcount += 1

    if tcount == ntests:
        print "All tests passed!"
        exit(0)
    else:
        print "%d tests failed" % (ntests-tcount)
        exit(1)
