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
GSS constants module

Provide constant values and mapping dictionaries for the GSS layer.
"""
import nfstest_config as c

# Module constants
__author__    = 'Jorge Mora (%s)' % c.NFSTEST_AUTHOR_EMAIL
__version__   = '1.0.1'
__copyright__ = "Copyright (C) 2013 NetApp, Inc."
__license__   = "GPL v2"

# rpc_gss_service_t
rpc_gss_svc_none         = 1
rpc_gss_svc_integrity    = 2
rpc_gss_svc_privacy      = 3
rpc_gss_svc_channel_prot = 4
gss_service = {
    1: 'rpc_gss_svc_none',
    2: 'rpc_gss_svc_integrity',
    3: 'rpc_gss_svc_privacy',
    4: 'rpc_gss_svc_channel_prot',
}

# rpc_gss_proc_t
RPCSEC_GSS_DATA          = 0
RPCSEC_GSS_INIT          = 1
RPCSEC_GSS_CONTINUE_INIT = 2
RPCSEC_GSS_DESTROY       = 3
RPCSEC_GSS_BIND_CHANNEL  = 4
gss_proc = {
    0: 'RPCSEC_GSS_DATA',
    1: 'RPCSEC_GSS_INIT',
    2: 'RPCSEC_GSS_CONTINUE_INIT',
    3: 'RPCSEC_GSS_DESTROY',
    4: 'RPCSEC_GSS_BIND_CHANNEL',
}

# rgss2_bind_chan_status
RGSS2_BIND_CHAN_OK           = 0
RGSS2_BIND_CHAN_PREF_NOTSUPP = 1
RGSS2_BIND_CHAN_HASH_NOTSUPP = 2
gss_bind_chan_stat = {
    0: 'RGSS2_BIND_CHAN_OK',
    1: 'RGSS2_BIND_CHAN_PREF_NOTSUPP',
    2: 'RGSS2_BIND_CHAN_HASH_NOTSUPP',
}

RPCSEC_GSS_VERS_1 = 1
RPCSEC_GSS_VERS_2 = 2
