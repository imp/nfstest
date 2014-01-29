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
NFS utilities module

Provides a set of tools for testing NFS including methods for starting a packet
trace, stopping the packet trace and then open the packet trace for analysis.
It also provides a mechanism to enable NFS/RPC kernel debug and saving the
log messages for further analysis.

Furthermore, methods for finding specific NFSv4 operations within the packet
trace is also included.
"""
import os
import re
import time
import subprocess
from host import Host
import nfstest_config as c
from packet.pktt import Pktt
from packet.nfs.nfs4_const import *

# Module constants
__author__    = 'Jorge Mora (%s)' % c.NFSTEST_AUTHOR_EMAIL
__version__   = '1.0.5'
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"

class NFSUtil(Host):
    """NFSUtil object

       NFSUtil() -> New NFSUtil object

       Usage:
           from nfstest.nfs_util import NFSUtil

           # Create object for local host
           x = NFSUtil()

           # Start packet trace
           x.trace_start()

           # Stop packet trace
           x.trace_stop()

           # Open packet trace
           x.trace_open()

           # Enable NFS kernel debug
           x.nfs_debug_enable(nfsdebug='all'):

           # Stop NFS kernel debug
           x.nfs_debug_reset()
    """
    def __init__(self, **kwargs):
        """Constructor

           Initialize object's private data.

           rpcdebug:
               Set RPC kernel debug flags and save log messages [default: '']
           nfsdebug:
               Set NFS kernel debug flags and save log messages [default: '']
           dbgname:
               Base name for log messages files to create [default: 'dbgfile']
           tracename:
               Base name for trace files to create [default: 'tracefile']
           trcdelay:
               Seconds to delay before stopping packet trace [default: 0.0]
           notrace:
               Debug option so a trace is not actually started [default: False]
           tcpdump:
               Tcpdump command [default: '/usr/sbin/tcpdump']
           messages:
               Location of file for system messages [default: '/var/log/messages']
           tmpdir:
               Temporary directory where trace files are created [default: '/tmp']
           tbsize:
               Capture buffer size in kB [default: 50000]
        """
        # Arguments
        self.rpcdebug  = kwargs.pop("rpcdebug",  '')
        self.nfsdebug  = kwargs.pop("nfsdebug",  '')
        self.dbgname   = kwargs.pop("dbgname",   'dbgfile')
        self.tracename = kwargs.pop("tracename", 'tracefile')
        self.trcdelay  = kwargs.pop("trcdelay",  0.0)
        self.notrace   = kwargs.pop("notrace",   False)
        self.tcpdump   = kwargs.pop("tcpdump",   c.NFSTEST_TCPDUMP)
        self.messages  = kwargs.pop("messages",  c.NFSTEST_MESSAGESLOG)
        self.tmpdir    = kwargs.pop("tmpdir",    c.NFSTEST_TMPDIR)
        self.tbsize    = kwargs.pop("tbsize",    50000)
        self._nfsdebug = False
        Host.__init__(self)

        # Initialize object variables
        self.dbgidx = 1
        self.dbgfile = ''
        self.traceidx = 1
        self.tracefile = ''
        self.tracefiles = []
        self.clients = []
        self.clientobj = None
        self.traceproc = None
        self.nii_name = ''    # nii_name for the client
        self.nii_server = ''  # nii_name for the server
        self.device_info = {}
        self.dslist = []
        self.stateid = None
        self.dsismds = False

        # Initialize all test variables
        self.writeverf    = None
        self.test_seqid   = True
        self.test_stateid = True
        self.test_pattern = True
        self.test_niomiss = 0
        self.test_stripe  = True
        self.test_verf    = True
        self.need_commit  = False
        self.need_lcommit = False
        self.mdsd_lcommit = False
        self.max_iosize   = 0
        self.error_hash   = {}
        self.test_commit_full = True
        self.test_no_commit   = False
        self.test_commit_verf = True

    def __del__(self):
        """Destructor

           Gracefully stop the packet trace and unreference all client
           objects
        """
        self.trace_stop()
        self.clientobj = None
        while self.clients:
            self.clients.pop()
        # Call base destructor
        Host.__del__(self)

    def create_host(self, host, **kwargs):
        """Create client host object and set defaults."""
        self.clientobj = Host(
            host         = host,
            user         = kwargs.pop("user", ""),
            server       = kwargs.pop("server",       self.server),
            nfsversion   = kwargs.pop("nfsversion",   self.nfsversion),
            minorversion = kwargs.pop("minorversion", self.minorversion),
            proto        = kwargs.pop("proto",        self.proto),
            port         = kwargs.pop("port",         self.port),
            sec          = kwargs.pop("sec",          self.sec),
            export       = kwargs.pop("export",       self.export),
            mtpoint      = kwargs.pop("mtpoint",      self.mtpoint),
            datadir      = kwargs.pop("datadir",      self.datadir),
            mtopts       = kwargs.pop("mtopts",       self.mtopts),
            nomount      = kwargs.pop("nomount",      self.nomount),
            sudo         = kwargs.pop("sudo",         self.sudo),
        )

        self.clients.append(self.clientobj)
        return self.clientobj

    def trace_start(self, tracefile=None, interface=None, capsize=None, clients=None):
        """Start trace on interface given

           tracefile:
               Name of trace file to create, default is a unique name
               created in the temporary directory using self.tracename as the
               base name.
           capsize:
               Use the -C option of tcpdump to split the trace files every
               1000000*capsize bytes. See documentation for tcpdump for more
               information
           clients:
               List of Host() objects to monitor

           Return the name of the trace file created.
        """
        self.trace_stop()
        if tracefile:
            self.tracefile = tracefile
        else:
            self.tracefile = "%s/%s_%d.cap" % (self.tmpdir, self.tracename, self.traceidx)
            self.traceidx += 1
        if not self.notrace:
            if len(self.nfsdebug) or len(self.rpcdebug):
                self.nfs_debug_enable()
            self.tracefiles.append(self.tracefile)

            if clients is None:
                clients = self.clients

            if interface is None:
                interface = self.interface

            opts = ""
            if interface is not None:
                opts += " -i %s" % interface

            if capsize:
                opts += " -C %d" % capsize

            hosts = self.ipaddr
            for cobj in clients:
                hosts += " or %s" % cobj.ipaddr

            cmd = "%s%s -n -B %d -s 0 -w %s host %s" % (self.tcpdump, opts, self.tbsize, self.tracefile, hosts)
            self.run_cmd(cmd, sudo=True, dlevel='DBG2', msg="Trace start: ", wait=False)
            self.traceproc = self.process

            # Make sure tcpdump has started
            out = self.traceproc.stderr.readline()
            if re.search('not found', out):
                raise Exception(out)
        return self.tracefile

    def trace_stop(self):
        """Stop the trace started by trace_start()."""
        try:
            if self.traceproc:
                self.dprint('DBG2', "Trace stop")
                time.sleep(self.trcdelay)
                self.stop_cmd(self.traceproc)
                self.traceproc = None
            if not self.notrace and self._nfsdebug:
                self.nfs_debug_reset()
        except:
            return

    def trace_open(self, tracefile=None, **kwargs):
        """Open the trace file given or the trace file started by trace_start().

           All extra options are passed directly to the packet trace object.

           Return the packet trace object created, the packet trace object
           is also stored in the object attribute pktt.
        """
        if tracefile is None:
            tracefile = self.tracefile
        self.dprint('DBG1', "trace_open [%s]" % tracefile)
        self.pktt = Pktt(tracefile, **kwargs)
        return self.pktt

    def nfs_debug_enable(self, **kwargs):
        """Enable NFS debug messages.

           rpcdebug:
               Set RPC kernel debug flags and save log messages [default: self.rpcdebug]
           nfsdebug:
               Set NFS kernel debug flags and save log messages [default: self.nfsdebug]
           dbgfile:
               Name of log messages file to create, default is a unique name
               created in the temporary directory using self.dbgname as the
               base name.
        """
        modmsgs = {
            'nfs': kwargs.pop('nfsdebug', self.nfsdebug),
            'rpc': kwargs.pop('rpcdebug', self.rpcdebug),
        }
        dbgfile = kwargs.pop('dbgfile', None)
        if dbgfile is not None:
            self.dbgfile = dbgfile
        else:
            self.dbgfile = "%s/%s_%d.msg" % (self.tmpdir, self.dbgname, self.dbgidx)
            self.dbgidx += 1

        if modmsgs['nfs'] is None and modmsgs['rpc'] is None:
            return

        if os.path.exists(self.messages):
            fstat = os.stat(self.messages)
            self.dbgoffset = fstat.st_size
            self.dbgmode = fstat.st_mode & 0777
            for mod in modmsgs.keys():
                if len(modmsgs[mod]):
                    self._nfsdebug = True
                    cmd = "rpcdebug -v -m %s -s %s" % (mod, modmsgs[mod])
                    self.run_cmd(cmd, sudo=True, dlevel='DBG2', msg="NFS debug enable: ")

    def nfs_debug_reset(self):
        """Reset NFS debug messages."""
        for mod in ('nfs', 'rpc'):
            try:
                cmd = "rpcdebug -v -m %s -c" % mod
                self.run_cmd(cmd, sudo=True, dlevel='DBG2', msg="NFS debug reset: ")
            except:
                pass

        if self.dbgoffset != None:
            try:
                fd = None
                fdw = None
                os.system(self.sudo_cmd("chmod %o %s" % (self.dbgmode|0444, self.messages)))
                self.dprint('DBG2', "Creating log messages file [%s]" % self.dbgfile)
                fdw = open(self.dbgfile, "w")
                fd = open(self.messages, "r")
                fd.seek(self.dbgoffset)
                while True:
                    data = fd.read(self.rsize)
                    if len(data) == 0:
                        break
                    fdw.write(data)
            except Exception as e:
                raise
            finally:
                if fd:
                    fd.close()
                if fdw:
                    fdw.close()
                os.system(self.sudo_cmd("chmod %o %s" % (self.dbgmode, self.messages)))

    def find_nfs_op(self, op, ipaddr, port=None, match='', status=0, src_ipaddr=None, maxindex=None, call_only=False):
        """Find the call and its corresponding reply for the specified NFSv4
           operation going to the server specified by the ipaddr and port.
           The reply must also match the given status.

           op:
               NFS operation to find
           ipaddr:
               Destination IP address
           port:
               Destination port [default: any destination port]
           match:
               Match string to include [default: '']
           status:
               Match the status of the operation [default: 0]
           src_ipaddr:
               Source IP address [default: any IP address]
           maxindex:
               The match fails if packet index hits this limit [default: no limit]
           call_only:
               Find the call only [default: False]

           Return a tuple: (pktcall, pktreply).
        """
        mstatus = "" if status is None else "NFS.status == %d and " % status
        src = "IP.src == '%s' and " % src_ipaddr if src_ipaddr != None else ''
        dst = "IP.dst == '%s' and " % ipaddr
        if len(match):
            match += " and "
        if port != None:
            dst += "TCP.dst_port == %d and " % port
        pktcall   = None
        pktreply  = None
        while True:
            # Find request
            pktcall = self.pktt.match(src + dst + match + "NFS.argop == %d" % op, maxindex=maxindex)
            if pktcall and not call_only:
                # Find reply
                xid = pktcall.rpc.xid
                pktreply = self.pktt.match("RPC.xid == %d and %s NFS.resop == %d" % (xid, mstatus, op), maxindex=maxindex)
                if pktreply:
                    break
            else:
                break
        return (pktcall, pktreply)

    def find_open(self, **kwargs):
        """Find the call and its corresponding reply for the NFSv4 OPEN of the
           given file going to the server specified by the ipaddr and port.

           filename:
               Find open call and reply for this file [default: None]
           claimfh:
               Find open call and reply for this file handle [default: None]
           ipaddr:
               Destination IP address [default: self.server]
           port:
               Destination port [default: self.port]
           deleg_type:
               Expected delegation type on reply [default: None]
           deleg_stateid:
               Delegation stateid expected on call in delegate_cur_info [default: None]
           src_ipaddr:
               Source IP address [default: any IP address]
           maxindex:
               The match fails if packet index hits this limit [default: no limit]
           anyclaim:
               Find open for either regular open or using delegate_cur_info [default: False]

           Must specify either filename, claimfh or both.
           Return a tuple: (filehandle, open_stateid, deleg_stateid).
        """
        filename      = kwargs.pop('filename', None)
        claimfh       = kwargs.pop('claimfh', None)
        ipaddr        = kwargs.pop('ipaddr', self.server_ipaddr)
        port          = kwargs.pop('port', self.port)
        deleg_type    = kwargs.pop('deleg_type', None)
        deleg_stateid = kwargs.pop('deleg_stateid', None)
        src_ipaddr    = kwargs.pop('src_ipaddr', None)
        maxindex      = kwargs.pop('maxindex', None)
        anyclaim      = kwargs.pop('anyclaim', False)

        src = "IP.src == '%s' and " % src_ipaddr if src_ipaddr is not None else ''
        dst = self.pktt.ip_tcp_dst_expr(ipaddr, port)

        file_str = ""
        deleg_str = ""
        claimfh_str = ""
        str_list = []
        if filename is not None:
            file_str = "NFS.claim.file == '%s'" % filename
            str_list.append(file_str)
        if claimfh is not None:
            claimfh_str = "(NFS.object == '%s' and NFS.claim.claim == %d)" % (self.pktt.escape(claimfh), CLAIM_FH)
            str_list.append(claimfh_str)
        if deleg_stateid is not None:
            deleg_str = "(NFS.claim.delegate_cur_info.file == '%s'" % filename
            deleg_str += " and NFS.claim.delegate_cur_info.delegate_stateid.other == '%s')" % self.pktt.escape(deleg_stateid)
            str_list.append(deleg_str)

        if anyclaim:
            file_str = " or ".join(str_list)
        elif claimfh is not None:
            file_str = claimfh_str
        elif deleg_stateid is not None:
            file_str = deleg_str
        elif len(file_str) == 0:
            raise Exception("Must specify either filename or claimfh")

        while True:
            pktcall = self.pktt.match(src + dst + " and NFS.argop == %d and %s" % (OP_OPEN, file_str), maxindex=maxindex)
            if not pktcall:
                return (None, None, None)
            xid = pktcall.rpc.xid
            open_str = "RPC.xid == %d and NFS.status == 0 and NFS.resop == %d" % (xid, OP_OPEN)
            if deleg_type is not None:
                open_str += " and NFS.delegation.delegation_type == %d" % deleg_type

            # Find OPEN reply to get filehandle of file
            pktreply = self.pktt.match(open_str, maxindex=maxindex)
            if not pktreply:
                continue

            if claimfh is None:
                # GETFH should be the operation following the OPEN,
                # but look for it just in case it is not
                idx = pktreply.NFSidx + 1
                resarray = pktreply.nfs.resarray
                while (idx < len(resarray) and resarray[idx].resop != OP_GETFH):
                    idx += 1
                if idx >= len(resarray):
                    # Could not find GETFH
                    return (None, None, None)
                filehandle = pktreply.nfs.resarray[idx].object
            else:
                # No need to find GETFH, the filehandle is already known
                filehandle = claimfh

            open_stateid = pktreply.NFSop.stateid.other
            if pktreply.NFSop.delegation.delegation_type in [OPEN_DELEGATE_READ, OPEN_DELEGATE_WRITE]:
                deleg_stateid = pktreply.NFSop.delegation.stateid.other
            else:
                deleg_stateid = None

            return (filehandle, open_stateid, deleg_stateid)

    def find_layoutget(self, filehandle):
        """Find the call and its corresponding reply for the NFSv4 LAYOUTGET
           of the given file handle going to the server specified by the
           ipaddr for self.server and port given by self.port.

           Return a tuple: (layoutget, layoutget_res, loc_body).
        """
        dst = self.pktt.ip_tcp_dst_expr(self.server_ipaddr, self.port)

        # Find LAYOUTGET request
        pkt = self.pktt.match(dst + " and NFS.argop == %d and NFS.object == '%s'" % (OP_LAYOUTGET, self.pktt.escape(filehandle)))
        if not pkt:
            return (None, None, None)
        xid = pkt.rpc.xid
        idx = pkt.NFSidx
        # The matched operation index (NFSidx) gives the PUTFH prior to the LAYOUTGET
        # since NFS.object is the last match
        layoutget = pkt.nfs.argarray[idx+1]

        # Find LAYOUTGET reply
        pkt = self.pktt.match("RPC.xid == %d and NFS.resop == %d" % (xid, OP_LAYOUTGET))
        if pkt is None:
            return (layoutget, None, None)
        layoutget_res = pkt.NFSop
        if layoutget_res.logr_status:
            return (layoutget, layoutget_res, None)
        # XXX Using first layout segment only
        layout = layoutget_res.logr_layout[0]

        # Get layout content
        loc_body = layout.lo_content.loc_body
        if layoutget.loga_layout_type == LAYOUT4_NFSV4_1_FILES:
            nfl_util = loc_body.nfl_util

            # Decode loc_body
            loc_body = {
                'type':               layoutget.loga_layout_type,
                'dense':              (nfl_util & NFL4_UFLG_DENSE > 0),
                'commit_mds':         (nfl_util & NFL4_UFLG_COMMIT_THRU_MDS > 0),
                'stripe_size':        nfl_util & NFL4_UFLG_STRIPE_UNIT_SIZE_MASK,
                'first_stripe_index': loc_body.nfl_first_stripe_index,
                'offset':             loc_body.nfl_pattern_offset,
                'filehandles':        loc_body.nfl_fh_list,
                'deviceid':           loc_body.nfl_deviceid,
                'stateid':            layoutget_res.logr_stateid.other,
                'iomode':             layout.lo_iomode,
            }
        else:
            loc_body = {
                'type':               layoutget.loga_layout_type,
                'stateid':            layoutget_res.logr_stateid.other,
                'iomode':             layout.lo_iomode,
            }

        return (layoutget, layoutget_res, loc_body)

    def find_getdeviceinfo(self, deviceid=None):
        """Find the call and its corresponding reply for the NFSv4 GETDEVICEINFO
           going to the server specified by the ipaddr for self.server and port
           given by self.port.

           deviceid:
               Look for an specific deviceid [default: any deviceid]

           Return a tuple: (pktcall, pktreply, dslist).
        """
        dslist = []
        # Find GETDEVICEINFO request and reply
        match = "NFS.gdia_device_id == '%s'" % self.pktt.escape(deviceid) if deviceid is not None else ''
        (pktcall, pktreply) = self.find_nfs_op(OP_GETDEVICEINFO, self.server_ipaddr, self.port, match=match, status=None)
        if pktreply and pktreply.nfs.status == 0:
            self.gdir_device = pktreply.NFSop.gdir_device_addr
            if self.gdir_device.da_layout_type == LAYOUT4_NFSV4_1_FILES:
                da_addr_body = self.gdir_device.da_addr_body
                self.stripe_indices = da_addr_body.nflda_stripe_indices
                multipath_ds_list = da_addr_body.nflda_multipath_ds_list

                for ds_list in multipath_ds_list:
                    for item in ds_list:
                        # Get ip address and port for DS
                        addr_list = item.na_r_addr.split('.')
                        ipaddr = '.'.join(addr_list[:4])
                        port = (int(addr_list[4])<<8) + int(addr_list[5])
                        dslist.append({'ipaddr': ipaddr, 'port': port})
            # Save device info for future reference
            self.device_info[pktcall.NFSop.gdia_device_id] = {
                'call':  pktcall,
                'reply': pktreply,
            }
        if len(dslist) > 0:
            self.dslist = dslist
        return (pktcall, pktreply, dslist)

    def find_exchange_id(self, **kwargs):
        """Find the call and its corresponding reply for the NFSv4 EXCHANGE_ID
           going to the server specified by the ipaddr and port.

           ipaddr:
               Destination IP address [default: self.server]
           port:
               Destination port [default: self.port]

           Store the callback IP/TCP expression in object attribute cb_dst

           Return a tuple: (pktcall, pktreply).
        """
        ipaddr = kwargs.pop('ipaddr', self.server_ipaddr)
        port   = kwargs.pop('port', self.port)
        # Find EXCHANGE_ID request and reply
        (pktcall, pktreply) = self.find_nfs_op(OP_EXCHANGE_ID, ipaddr, port)
        self.src_ipaddr = pktcall.ip.src
        self.src_port   = pktcall.tcp.src_port
        self.cb_dst     = self.pktt.ip_tcp_dst_expr(self.src_ipaddr, self.src_port)
        try:
            if len(pktcall.NFSop.eia_client_impl_id) > 0:
                self.nii_name = pktcall.NFSop.eia_client_impl_id[0].nii_name
        except:
            pass
        try:
            if len(pktreply.NFSop.eir_server_impl_id) > 0:
                self.nii_server = pktreply.NFSop.eir_server_impl_id[0].nii_name
        except:
            pass
        return (pktcall, pktreply)

    def find_layoutrecall(self, status=0):
        """Find NFSv4 CB_LAYOUTRECALL call and return its reply.
           The reply must also match the given status.
        """
        # Find CB_LAYOUTRECALL request
        pktcall = self.pktt.match(self.cb_dst + " and NFS.argop == %d" % OP_CB_LAYOUTRECALL)
        if pktcall:
            # Find reply
            xid = pktcall.rpc.xid
            pktreply = self.pktt.match("RPC.xid == %d and NFS.resop == %d and NFS.clorr_status == %d" % (xid, OP_CB_LAYOUTRECALL, status))
        else:
            self.test(False, "CB_LAYOUTRECALL was not found")
            return
        return pktreply

    def get_abs_offset(self, offset, ds_index=None):
        """Get real file offset given by the (read/write) offset on the given
           data server index, taking into account the type of layout
           (dense/sparse), the stripe_size, first stripe index and the number
           of filehandles. The layout information is taken from object
           attribute layout.
        """
        if ds_index is None:
            return offset
        nfhs = len(self.dslist)
        stripe_size = self.layout['stripe_size']
        first_stripe_index = self.layout['first_stripe_index']
        ds_index -= first_stripe_index;
        if ds_index < 0:
            ds_index += nfhs
        # Get real file offset given by the read/write offset to the given DS index
        if self.layout['dense']:
            # Dense layout
            n = int(offset / stripe_size)
            r = offset % stripe_size
            file_offset = (n*nfhs + ds_index)*stripe_size + r
        else:
            # Sparse layout
            file_offset = offset
        return file_offset

    def get_filehandle(self, ds_index):
        """Return filehandle from the layout list of filehandles."""
        if len(self.layout['filehandles']) > 1:
            filehandle = self.layout['filehandles'][ds_index]
        else:
            filehandle = self.layout['filehandles'][0]
        return filehandle

    def verify_stripe(self, offset, size, ds_index):
        """Verify if read/write is sent to the correct data server according
           to stripe size, first stripe index and the number of filehandles.
           The layout information is taken from object attribute layout.

           offset:
               Real file offset
           size:
               I/O size
           ds_index:
               Data server index

           Return True if stripe is correctly verified, False otherwise.
        """
        nfhs = len(self.dslist)
        if self.layout is None or ds_index is None:
            return False
        stripe_size = self.layout['stripe_size']
        first_stripe_index = self.layout['first_stripe_index']
        n = int(offset / stripe_size)
        m = int((offset + size - 1) / stripe_size)
        idx = n % nfhs
        ds_index -= first_stripe_index;
        if ds_index < 0:
            ds_index += nfhs
        return n == m and idx == ds_index

    def verify_create_session(self, ipaddr, port, ds=False, nocreate=False, ds_index=None, exchid_status=0, cs_status=0):
        """Verify initial connection to the metadata server(MDS)/data server(DS).
           Verify if EXCHANGE_ID, CREATE_SESSION, RECLAIM_COMPLETE,
           GETATTR asking for FATTR4_LEASE_TIME, and GETATTR asking for
           FATTR4_FS_LAYOUT_TYPE are all sent or not to the server.

           ipaddr:
               Destination IP address of MDS or DS
           port:
               Destination port number of MDS or DS
           ds:
               True if ipaddr/port defines a DS, otherwise MDS [default: False]
           nocreate:
               True if expecting the client NOT to send EXCHANGE_ID,
               CREATE_SESSION, and RECLAIM_COMPLETE. Otherwise, verify all
               these operations are sent by the client [default: False]
           ds_index:
               DS index used for displaying purposes only [default: None]
           exchid_status:
               Expected status for EXCHANGE_ID [default: 0]
           cs_status:
               Expected status for CREATE_SESSION [default: 0]

           Return the sessionid and it is also stored in the object
           attribute sessionid.
        """
        self.sessionid = None
        if ds:
            pnfs_use_flag = EXCHGID4_FLAG_USE_PNFS_DS
            server_type = "DS"
            if ds_index is not None:
                server_type += "(%d)" % ds_index
        else:
            pnfs_use_flag = EXCHGID4_FLAG_USE_PNFS_MDS
            server_type = "MDS"

        dsmds = ""
        if ds_index != None and ipaddr == self.server_ipaddr and port == self.port:
            # DS == MDS, client does not connect to DS, it has a connection already
            nocreate = True
            dsmds = " since DS == MDS"

        # Find EXCHANGE_ID request and reply
        (pktcall, pktreply) = self.find_nfs_op(OP_EXCHANGE_ID, ipaddr, port, status=exchid_status)
        if nocreate:
            self.test(not pktcall, "EXCHANGE_ID should not be sent to %s%s" % (server_type, dsmds))
        else:
            self.test(pktcall, "EXCHANGE_ID should be sent to %s" % server_type)
            if pktreply:
                if exchid_status:
                    self.test(pktreply.NFSop.eir_status == exchid_status, "EXCHANGE_ID reply should return %s(%d)" % (nfsstat4[exchid_status], exchid_status))
                    return
                else:
                    eir_flags = pktreply.NFSop.eir_flags
                    if len(pktreply.NFSop.eir_server_impl_id) > 0:
                        self.nii_name = pktreply.NFSop.eir_server_impl_id[0].nii_name
                    self.test(eir_flags & pnfs_use_flag != 0, "EXCHGID4_FLAG_USE_PNFS_%s should be set" % server_type, terminate=True)
                    if not ds:
                        # Check for invalid combination of eir flags
                        self.test(eir_flags & EXCHGID4_FLAG_USE_NON_PNFS == 0, "EXCHGID4_FLAG_USE_NON_PNFS should not be set")
            else:
                self.test(False, "EXCHANGE_ID reply was not found")

        # Find CREATE_SESSION request
        (pktcall, pktreply) = self.find_nfs_op(OP_CREATE_SESSION, ipaddr, port, status=cs_status)
        if nocreate:
            self.test(not pktcall, "CREATE_SESSION should not be sent to %s%s" % (server_type, dsmds))
        else:
            self.test(pktcall, "CREATE_SESSION should be sent to %s" % server_type)
            if pktreply:
                if cs_status:
                    self.test(pktreply.NFSop.csr_status == cs_status, "CREATE_SESSION reply should return %s(%d)" % (nfsstat4[cs_status], cs_status))
                    return
                else:
                    # Save the session id
                    self.sessionid = pktreply.NFSop.csr_sessionid
                    # Save the max response size
                    self.ca_maxrespsz = pktreply.NFSop.csr_fore_chan_attrs.ca_maxresponsesize

                    slotid = 0
                    fmsg = None
                    test_seq = True
                    save_index = self.pktt.index
                    while True:
                        # Find first SEQUENCE requests per slot id
                        (pktcall, pktreply) = self.find_nfs_op(OP_SEQUENCE, ipaddr, port, call_only=True, match="NFS.sa_slotid == %d" % slotid)
                        if pktcall is None:
                            break
                        self.pktt.rewind(save_index)
                        slotid += 1
                        if pktcall.NFSop.sa_sequenceid != 1:
                            fmsg = ", slot id %d starts with sequence id %d" % (slotid-1, pktcall.NFSop.sa_sequenceid)
                            test_seq = False
                            break
                    if slotid > 0:
                        self.test(test_seq, "SEQUENCE request should start with a sequence id of 1", failmsg=fmsg)
                    else:
                        self.test(False, "SEQUENCE request was not found")
                    self.pktt.rewind(save_index)
            elif pktcall:
                self.test(False, "CREATE_SESSION reply was not found")

        # Find RECLAIM_COMPLETE request
        (pktcall, pktreply) = self.find_nfs_op(OP_RECLAIM_COMPLETE, ipaddr, port, status=None)
        if nocreate:
            self.test(not pktcall, "RECLAIM_COMPLETE should not be sent to %s%s" % (server_type, dsmds))
        else:
            self.test(pktcall, "RECLAIM_COMPLETE should be sent to %s" % server_type)

        if not ds:
            # Find packet having a GETATTR asking for FATTR4_LEASE_TIME(bit 10)
            attrmatch = "NFS.attr_request & %s != 0" % hex(1 << FATTR4_LEASE_TIME)
            (pktcall, pktreply) = self.find_nfs_op(OP_GETATTR, self.server_ipaddr, self.port, match=attrmatch)
            self.test(pktcall, "GETATTR should be sent to %s asking for FATTR4_LEASE_TIME" % server_type)
            if pktreply:
                lease_time = pktreply.NFSop.obj_attributes[FATTR4_LEASE_TIME]
                self.test(lease_time > 0, "NFS server should return lease time(%d) > 0" % lease_time)
            elif pktcall:
                self.test(False, "GETATTR reply was not found")

            # Find packet having a GETATTR asking for FATTR4_SUPPORTED_ATTRS(bit 0)
            attrmatch = "NFS.attr_request & %s != 0" % hex(1 << FATTR4_SUPPORTED_ATTRS)
            (pktcall, pktreply) = self.find_nfs_op(OP_GETATTR, self.server_ipaddr, self.port, match=attrmatch)
            self.test(pktcall, "GETATTR should be sent to %s asking for FATTR4_SUPPORTED_ATTRS" % server_type)
            if pktreply:
                supported_attrs = pktreply.NFSop.obj_attributes[FATTR4_SUPPORTED_ATTRS]
                fslt_supported = supported_attrs & (1<<FATTR4_FS_LAYOUT_TYPE) != 0
                self.test(fslt_supported, "NFS server should support file type layouts (LAYOUT4_NFSV4_1_FILES)")
            elif pktcall:
                self.test(False, "GETATTR reply was not found")

            # Find packet having a GETATTR asking for FATTR4_FS_LAYOUT_TYPE(bit 62)
            attrmatch = "NFS.attr_request & %s != 0" % hex(1 << FATTR4_FS_LAYOUT_TYPE)
            (pktcall, pktreply) = self.find_nfs_op(OP_GETATTR, self.server_ipaddr, self.port, match=attrmatch)
            self.test(pktcall, "GETATTR should be sent to %s asking for FATTR4_FS_LAYOUT_TYPE" % server_type)
            if pktreply:
                # Get list of fs layout types supported by the server
                fs_layout_types = pktreply.NFSop.obj_attributes[FATTR4_FS_LAYOUT_TYPE]
                self.test(LAYOUT4_NFSV4_1_FILES in fs_layout_types, "NFS server should return LAYOUT4_NFSV4_1_FILES in fs_layout_types")
            elif pktcall:
                self.test(False, "GETATTR reply was not found")
        return self.sessionid

    def verify_layoutget(self, filehandle, iomode, riomode=None, status=0, offset=None, length=None):
        """Verify the client sends a LAYOUTGET for the given file handle.

           filehandle:
               Find LAYOUTGET for this file handle
           iomode:
               Expected I/O mode for LAYOUTGET call
           riomode:
               Expected I/O mode for LAYOUTGET reply if specified, else verify
               reply I/O mode is equal to call I/O mode if iomode == 2.
               If iomode == 1, the reply I/O mode could be equal to 1 or 2
           status:
               Expected status for LAYOUTGET reply [default: 0]
           offset:
               Expected layout range for LAYOUTGET reply [default: None]
           length:
               Expected layout range for LAYOUTGET reply [default: None]

           If both offset and length are not given, verify LAYOUTGET reply
           should be a full layout [0, NFS4_UINT64_MAX]. If only one is
           provided the following defaults are used: offset = 0,
           length = NFS4_UINT64_MAX.

           Layout information is stored in the object attribute layout.

           Return a tuple: (layoutget, layoutget_res, loc_body).
        """
        # Find LAYOUTGET for given filehandle
        layoutget, layoutget_res, loc_body = self.find_layoutget(filehandle)
        if layoutget is None:
            self.layout = None
            return (None, None, None)

        # Test layout type
        self.test(layoutget.loga_layout_type == LAYOUT4_NFSV4_1_FILES, "LAYOUTGET layout type should be LAYOUT4_NFSV4_1_FILES")

        # Test iomode
        self.test(layoutget.loga_iomode == iomode, "LAYOUTGET iomode should be %s" % self.iomode_str(iomode))

        # Test for full file layout
        self.test(layoutget.loga_offset == 0 and layoutget.loga_length == NFS4_UINT64_MAX, "LAYOUTGET should ask for full file layout")

        if layoutget_res is None:
            self.test(False, "LAYOUTGET reply should be returned")
            return (layoutget, None, None)

        if status:
            self.test(layoutget_res.logr_status == status, "LAYOUTGET reply should return error %s(%d)" % (nfsstat4[status], status))
            return (layoutget, layoutget_res, None)
        elif layoutget_res.logr_status:
            self.test(False, "LAYOUTGET reply returned %s(%d)" % (nfsstat4[layoutget_res.logr_status], layoutget_res.logr_status))
            return (layoutget, layoutget_res, None)

        # Get layout from reply
        layout = layoutget_res.logr_layout[0]

        # Test LAYOUTGET reply for correct layout type
        self.test(layout.lo_content.loc_type == LAYOUT4_NFSV4_1_FILES, "LAYOUTGET reply layout type should be LAYOUT4_NFSV4_1_FILES")

        # Test LAYOUTGET reply for correct iomode
        if riomode is not None:
            self.test(layout.lo_iomode == riomode, "LAYOUTGET reply iomode is %s when asking for a %s layout" % (self.iomode_str(riomode), self.iomode_str(iomode)))
        elif iomode == 1 and layoutget.loga_iomode in [LAYOUTIOMODE4_READ, LAYOUTIOMODE4_RW]:
            self.test(True, "LAYOUTGET reply iomode is %s when asking for a IOMODE_READ layout" % self.iomode_str(layoutget.loga_iomode))
        else:
            self.test(layout.lo_iomode == iomode, "LAYOUTGET reply iomode should be %s" % self.iomode_str(iomode))

        if offset is None and length is None:
            # Test LAYOUTGET reply for full file layout
            self.test(layout.lo_offset == 0 and layout.lo_length == NFS4_UINT64_MAX, "LAYOUTGET reply should be full file layout")
        else:
            # Test LAYOUTGET reply for correct layout range
            if offset is None:
                offset = 0
            if length is None:
                length = NFS4_UINT64_MAX
            self.test(layout.lo_offset == offset and layout.lo_length == length, "LAYOUTGET reply should be: (offset=%d, length=%d)" % (offset, length))

        # Return layout
        self.layout = loc_body
        self.layout['return_on_close'] = layoutget_res.logr_return_on_close
        return (layoutget, layoutget_res, loc_body)

    def verify_io(self, iomode, stateid, ipaddr=None, port=None, src_ipaddr=None, filehandle=None, ds_index=None, init=False, maxindex=None, pattern=None):
        """Verify I/O is sent to the server specified by the ipaddr and port.

           iomode:
               Verify reads (iomode == 1) or writes (iomode == 2)
           stateid:
               Expected stateid to use in all I/O requests
           ipaddr:
               Destination IP address of MDS or DS
               [default: do not match destination]
           port:
               Destination port number of MDS or DS
               [default: do not match destination port]
           src_ipaddr:
               Source IP address of request
               [default: do not match source]
           filehandle:
               Find I/O for this file handle. This option is used when
               verifying I/O sent to the MDS
               [default: use filehandle given by ds_index]
           ds_index:
               Data server index. This option is used when verifying I/O sent
               to the DS -- filehandle is taken from x.layout for this index
               [default: None]
           init:
               Initialized test variables [default: False]
           maxindex:
               The match fails if packet index hits this limit [default: no limit]
           pattern:
               Data pattern to compare [default: default data pattern]

           Return the number of I/O operations sent to the server.
        """
        if filehandle is None:
            filehandle = self.get_filehandle(ds_index)
        src = "IP.src == '%s' and " % src_ipaddr if src_ipaddr != None else ''
        dst = ''
        if ipaddr != None:
            dst = "IP.dst == '%s' and " % ipaddr
            if port != None:
                dst += "TCP.dst_port == %d and " % port
        fh = "NFS.object == '%s'" % self.pktt.escape(filehandle)
        save_index = self.pktt.index
        xids = []
        offsets = {}
        good_pattern = 0
        bad_pattern = 0
        self.test_offsets = []
        if init:
            self.test_seqid   = True
            self.test_stateid = True
            self.test_pattern = True
            self.test_niomiss = 0
            self.test_stripe  = True
            self.test_verf    = True
            self.need_commit  = False
            self.need_lcommit = False
            self.mdsd_lcommit = False
            self.stateid      = None
            self.max_iosize   = 0
            self.error_hash   = {}

        # Get I/O type: iomode == 1 (READ), else (WRITE)
        io_op = OP_READ if iomode == LAYOUTIOMODE4_READ else OP_WRITE

        # Find all I/O requests for MDS or current DS
        while True:
            # Find I/O request
            pkt = self.pktt.match(src + dst + fh + " and NFS.argop == %d" % io_op, maxindex=maxindex)
            if not pkt:
                break
            xids.append(pkt.rpc.xid)
            nfsop = pkt.NFSop
            self.test_offsets.append(nfsop.offset)
            if iomode == LAYOUTIOMODE4_READ:
                offsets[pkt.rpc.xid] = nfsop.offset

            if nfsop.stateid.seqid != 0:
                self.test_seqid = False
            if nfsop.stateid.other != stateid:
                self.test_stateid = False
            self.stateid = nfsop.stateid.other

            # Get real file offset
            file_offset = self.get_abs_offset(nfsop.offset, ds_index)

            if iomode == LAYOUTIOMODE4_READ:
                size = nfsop.count
            else:
                data = self.data_pattern(file_offset, len(nfsop.data), pattern=pattern)
                if data != nfsop.data:
                    bad_pattern += 1
                else:
                    good_pattern += 1
                size = len(nfsop.data)
            if self.max_iosize < size:
                self.max_iosize = size

            # Check if I/O is sent to the MDS or correct DS according to stripe size
            if ds_index is not None and not self.verify_stripe(file_offset, size, ds_index):
                self.test_stripe = False

        # Rewind trace file to saved packet index
        self.pktt.rewind(save_index)

        if iomode == LAYOUTIOMODE4_RW:
            self.dprint('DBG7', "WRITE bad/good pattern %d/%d" % (bad_pattern, good_pattern))
            if good_pattern == 0 or float(bad_pattern)/good_pattern >= 0.25:
                self.test_pattern = False
            elif bad_pattern > 0:
                self.warning("Some WRITE packets were not capture properly")

        if len(xids) == 0:
            return 0

        # Find all I/O replies for MDS or current DS
        while True:
            # Find I/O reply
            pkt = self.pktt.match("NFS.resop == %d" % io_op, maxindex=maxindex)
            if not pkt:
                break
            xid = pkt.rpc.xid
            if xid in xids:
                xids.remove(xid)
                nfsop = pkt.NFSop

                if iomode == LAYOUTIOMODE4_READ:
                    offset = offsets[xid]

                    # Get real file offset
                    file_offset = self.get_abs_offset(offset, ds_index)

                    data = self.data_pattern(file_offset, len(nfsop.data), pattern=pattern)
                    if data != nfsop.data:
                        bad_pattern += 1
                    else:
                        good_pattern += 1
                else:
                    if pkt.nfs.status == NFS4_OK:
                        if not self.dsismds:
                            self.mdsd_lcommit = True
                        if nfsop.committed < FILE_SYNC4:
                            # Need layout commit if reply is not FILE_SYNC4
                            self.need_lcommit = True
                        if nfsop.committed == UNSTABLE4:
                            # Need commit if reply is UNSTABLE4
                            self.need_commit = True
                        if self.writeverf is None:
                            self.writeverf = nfsop.writeverf
                        if self.writeverf != nfsop.writeverf:
                            self.test_verf = False
                    else:
                        # Server returned error for this I/O operation
                        errstr = nfsstat4.get(pkt.nfs.status)
                        if self.error_hash.get(errstr) is None:
                            self.error_hash[errstr] = 1
                        else:
                            self.error_hash[errstr] += 1

                if len(xids) == 0:
                    break
            else:
                # Call was not found for this reply
                self.test_niomiss += 1
        # Add the number of calls with no replies
        self.test_niomiss += len(xids)
        nops = good_pattern + bad_pattern + self.test_niomiss

        if iomode == LAYOUTIOMODE4_READ:
            self.dprint('DBG7', "READ bad/good pattern %d/%d" % (bad_pattern, good_pattern))
            if good_pattern == 0 or float(bad_pattern)/good_pattern >= 0.25:
                self.test_pattern = False
            elif bad_pattern > 0:
                self.warning("Some READ packets were not capture properly")

        if len(xids) > 0:
            self.warning("Could not find all replies to %s" % ('READ' if iomode == LAYOUTIOMODE4_READ else 'WRITE'))

        return nops

    def verify_commit(self, ipaddr, port, filehandle, init=False):
        """Verify commits are properly sent to the server specified by the
           given ipaddr and port.

           ipaddr:
               Destination IP address of MDS or DS
           port:
               Destination port number of MDS or DS
           filehandle:
               Find commits for this file handle
           init:
               Initialized test variables [default: False]

           Return the number of commits sent to the server.
        """
        dst = self.pktt.ip_tcp_dst_expr(ipaddr, port)
        fh = "NFS.object == '%s'" % self.pktt.escape(filehandle)
        save_index = self.pktt.index
        xids = []
        if init:
            self.test_commit_full = True
            self.test_no_commit   = False
            self.test_commit_verf = True

        while True:
            # Find COMMIT request for current DS
            pkt = self.pktt.match(dst + " and " + fh + " and NFS.argop == %d" % OP_COMMIT)
            if not pkt:
                break
            xids.append(pkt.rpc.xid)
            nfscommit = pkt.NFSop
            if nfscommit.offset != 0 or nfscommit.count != 0:
                self.test_commit_full = False

        ncommits = len(xids)
        if ncommits == 0:
            # No COMMIT was found
            self.test_no_commit = True
            return 0

        # Rewind trace file to saved packet index
        self.pktt.rewind(save_index)
        while True:
            # Find COMMIT reply for current DS
            pkt = self.pktt.match("NFS.resop == %d" % OP_COMMIT)
            if not pkt:
                break
            if pkt.rpc.xid in xids:
                nfscommit = pkt.NFSop
                if self.writeverf != nfscommit.writeverf:
                    self.test_commit_verf = False

        return ncommits

    def verify_layoutcommit(self, filehandle, filesize):
        """Verify layoutcommit is properly sent to the server specified by
           the ipaddr for self.server and port given by self.port.
           Verify a GETATTR asking for file size is sent within the same
           compound as the LAYOUTCOMMIT.
           Verify GETATTR returns correct size for the file.

           filehandle:
               Find layoutcommit for this file handle
           filesize:
               Expected size of file
        """
        dst = self.pktt.ip_tcp_dst_expr(self.server_ipaddr, self.port)
        fh = "NFS.object == '%s'" % self.pktt.escape(filehandle)

        # Find LAYOUTCOMMIT request
        pkt = self.pktt.match(dst + " and " + fh + " and NFS.argop == %d" % OP_LAYOUTCOMMIT)
        if self.layout['commit_mds']:
            self.test(not pkt, "LAYOUTCOMMIT should not be sent to MDS when NFL4_UFLG_COMMIT_THRU_MDS is set")
        else:
            if self.need_lcommit:
                if self.mdsd_lcommit:
                    self.test(pkt, "LAYOUTCOMMIT should be sent to MDS when NFL4_UFLG_COMMIT_THRU_MDS is not set")
                else:
                    self.test(not pkt, "LAYOUTCOMMIT should not be sent to MDS when DS == MDS")
            else:
                self.test(not pkt, "LAYOUTCOMMIT should not be sent to MDS (FILE_SYNC4)")
            if not pkt:
                return

            xid = pkt.rpc.xid
            layoutcommit = pkt.NFSop
            range_expr = layoutcommit.loca_offset == 0 and layoutcommit.loca_length in (filesize, NFS4_UINT64_MAX)
            self.test(range_expr, "LAYOUTCOMMIT should be sent to MDS with correct file range")
            self.test(layoutcommit.loca_stateid.other == self.layout['stateid'], "LAYOUTCOMMIT should use the layout stateid")
            self.test(layoutcommit.loca_last_write_offset.no_newoffset, "LAYOUTCOMMIT new offset should be set")
            self.test(layoutcommit.loca_last_write_offset.no_offset == (filesize - 1),
                      "LAYOUTCOMMIT last write offset (%d) should be one less than the file size (%d)" % (layoutcommit.loca_last_write_offset.no_offset, filesize))
            self.test(layoutcommit.loca_layoutupdate.lou_type == LAYOUT4_NFSV4_1_FILES, "LAYOUTCOMMIT layout type should be LAYOUT4_NFSV4_1_FILES")
            self.test(len(layoutcommit.loca_layoutupdate.lou_body) == 0, "LAYOUTCOMMIT layout update field should be empty for LAYOUT4_NFSV4_1_FILES")

            # Verify a GETATTR asking for file size is sent with LAYOUTCOMMIT
            idx = pkt.NFSidx
            getattr_arg = pkt.nfs.argarray[idx+1]
            self.test(getattr_arg.attr_request & (1 << FATTR4_SIZE), "GETATTR asking for file size is sent within LAYOUTCOMMIT compound")

            # Find LAYOUTCOMMIT reply
            pkt = self.pktt.match("RPC.xid == %d and NFS.resop == %d" % (xid, OP_LAYOUTCOMMIT))
            layoutcommit = pkt.NFSop
            if layoutcommit.locr_newsize.ns_sizechanged:
                self.test(True, "LAYOUTCOMMIT reply file size changed should be set")
                ns_size = layoutcommit.locr_newsize.ns_size
                if ns_size == filesize:
                    self.test(True, "LAYOUTCOMMIT reply file size should be correct (%d)" % ns_size)
                else:
                    self.warning("LAYOUTCOMMIT reply file size is not correct (%d)" % ns_size)
            else:
                self.test(True, "LAYOUTCOMMIT reply file size changed is not set (ERRATA)")

            # Verify GETATTR returns correct file size
            idx = pkt.NFSidx
            getattr_res = pkt.nfs.resarray[idx+1]
            self.test(getattr_res.obj_attributes[FATTR4_SIZE] == filesize, "GETATTR should return correct file size within LAYOUTCOMMIT compound")
        return

    @staticmethod
    def iomode_str(iomode):
        """Return a string representation of iomode.
           This could be run as an instance or class method.
        """
        if layoutiomode4.get(iomode):
            return layoutiomode4[iomode]
        else:
            return str(iomode)

    @staticmethod
    def bitmap_str(bitmap, count, bmap, blist):
        """Return the string representation of bitmap.

           bitmap:
               Bitmap to convert
           count:
               Number of occurrences of bitmap
           bmap:
               Dictionary mapping the bits to strings
           blist:
               List of all possible bit combinations
        """
        # Get number of instances of bitmap
        cnt = 0
        for item in blist:
            if bitmap & item == bitmap:
                cnt += 1
        plist = []
        bit = max(bmap.keys())

        # Convert bitmap to a string
        while bit > 0:
            if bitmap & bit:
                plist.append(bmap[bit])
            bit = bit >> 1
        if cnt == count:
            return " & ".join(plist)
        return
