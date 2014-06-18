#===============================================================================
# Copyright 2013 NetApp, Inc. All Rights Reserved,
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
GSS module

Decode GSS layers.

NOTE:
  Only procedures RPCSEC_GSS_INIT and RPCSEC_GSS_DATA are supported
"""
from gss_const import *
from rpc_const import *
import nfstest_config as c
from baseobj import BaseObj
from packet.unpack import Unpack

# Module constants
__author__    = 'Jorge Mora (%s)' % c.NFSTEST_AUTHOR_EMAIL
__version__   = '1.0.1'
__copyright__ = "Copyright (C) 2013 NetApp, Inc."
__license__   = "GPL v2"

class GSS_Data(BaseObj):
    """GSS Data object

       This object is the representation of the data preceding the RPC
       payload when flavor is RPCSEC_GSS.
    """
    def __str__(self):
        """String representation of object

           The representation depends on the verbose level set by debug_repr().
           If set to 0 the generic object representation is returned.
           If set to 1 the representation of the object is:
               'GSSD length: 176, seq_num: 1'

           If set to 2 the representation of the object is as follows:
               'length: 176, seq_num: 1'
        """
        rdebug = self.debug_repr()
        rdata = ""
        if rdebug > 0:
            if self._proc == RPCSEC_GSS_DATA:
                rdata = "length: %d, seq_num: %d" % (self.length, self.seq_num)
            elif self._proc == RPCSEC_GSS_INIT:
                if self._type == CALL:
                    rdata = "token: 0x%s..." % self.token[:32].encode('hex')
                else:
                    rdata = "major: %d, " % self.major + \
                            "minor: %d, " % self.minor + \
                            "seq_window: %d, " % self.seq_window + \
                            "context: 0x%s, " % self.context.encode('hex') + \
                            "token: 0x%s..." % self.token[:16].encode('hex')
        if rdebug == 1:
            out = "GSSD %s" % rdata
        elif rdebug == 2:
            out = rdata
        else:
            out = BaseObj.__str__(self)
        return out

class GSS_Checksum(BaseObj):
    """GSS Checksum object

       This object is the representation of the data following the RPC
       payload when flavor is RPCSEC_GSS.
    """
    def __str__(self):
        """String representation of object

           The representation depends on the verbose level set by debug_repr().
           If set to 0 the generic object representation is returned.
           If set to 1 the representation of the object is:
               'GSSC token: 0x602306092a864886f71201020201010000...'

           If set to 2 the representation of the object is as follows:
               'token: 0x602306092a864886f71201020201010000...'
        """
        rdebug = self.debug_repr()
        rdata = ""
        if rdebug > 0:
            rdata = "token: 0x%s..." % self.token[:32].encode('hex')
        if rdebug == 1:
            out = "GSSC %s" % rdata
        elif rdebug == 2:
            out = rdata
        else:
            out = BaseObj.__str__(self)
        return out

class GSS(BaseObj, Unpack):
    """GSS Data object

       This is a base object and should not be instantiated.
       It gives the following methods:
           # Decode data preceding the RPC payload when flavor is RPCSEC_GSS
           x.decode_gss_data()

           # Decode data following the RPC payload when flavor is RPCSEC_GSS
           x.decode_gss_checksum()
    """
    def _gss_data_call(self):
        """Internal method to decode GSS data on a CALL"""
        if self.credential.flavor != RPCSEC_GSS:
            # Not a GSS encoded packet
            return
        if self.credential.gss_proc == RPCSEC_GSS_DATA:
            if self.credential.gss_service == rpc_gss_svc_integrity:
                return GSS_Data(
                    _type   = 0,
                    _proc   = RPCSEC_GSS_DATA,
                    length  = self.unpack_uint(),
                    seq_num = self.unpack_uint(),
                )
        elif self.credential.gss_proc == RPCSEC_GSS_INIT:
            return GSS_Data(
                _type = 0,
                _proc = RPCSEC_GSS_INIT,
                token = self.unpack_opaque(),
            )

    def _gss_data_reply(self):
        """Internal method to decode GSS data on a REPLY"""
        if self.verifier.flavor != RPCSEC_GSS or not hasattr(self.verifier, 'gss_proc'):
            # Not a GSS encoded packet
            return
        if self.verifier.gss_proc == RPCSEC_GSS_DATA:
            if self.verifier.gss_service == rpc_gss_svc_integrity:
                return GSS_Data(
                    _type   = 1,
                    _proc   = RPCSEC_GSS_DATA,
                    length  = self.unpack_uint(),
                    seq_num = self.unpack_uint(),
                )
        elif self.verifier.gss_proc == RPCSEC_GSS_INIT:
            return GSS_Data(
                _type      = 1,
                _proc      = RPCSEC_GSS_INIT,
                context    = self.unpack_opaque(),
                major      = self.unpack_uint(),
                minor      = self.unpack_uint(),
                seq_window = self.unpack_uint(),
                token      = self.unpack_opaque(),
            )

    def decode_gss_data(self):
        """Decode GSS data"""
        try:
            if len(self.data) < 4:
                # Not a GSS encoded packet
                return
            if self.type == CALL:
                gss = self._gss_data_call()
            else:
                gss = self._gss_data_reply()
            if gss is not None:
                self._pktt.pkt.gssd = gss
        except:
            pass

    def decode_gss_checksum(self):
        """Decode GSS checksum"""
        try:
            if len(self.data) < 4:
                # Not a GSS encoded packet
                return
            gss = None
            if self.type == CALL:
                if self.credential.flavor == RPCSEC_GSS and self.credential.gss_proc == RPCSEC_GSS_DATA:
                    if self.credential.gss_service == rpc_gss_svc_integrity:
                        gss = GSS_Checksum(token = self.unpack_opaque())
            else:
                if self.verifier.flavor == RPCSEC_GSS and self.verifier.gss_proc == RPCSEC_GSS_DATA:
                    if self.verifier.gss_service == rpc_gss_svc_integrity:
                        gss = GSS_Checksum(token = self.unpack_opaque())
            if gss is not None:
                self._pktt.pkt.gssc = gss
        except:
            pass
