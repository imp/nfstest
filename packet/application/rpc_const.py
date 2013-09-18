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
RPC constants module

Provide constant values and mapping dictionaries for the RPC layer.
"""
import nfstest_config as c

# Module constants
__author__    = 'Jorge Mora (%s)' % c.NFSTEST_AUTHOR_EMAIL
__version__   = '1.0.1'
__copyright__ = "Copyright (C) 2013 NetApp, Inc."
__license__   = "GPL v2"

# msg_type
CALL  = 0
REPLY = 1
msg_type = {
    0: 'CALL',
    1: 'REPLY',
}

# reply_stat
MSG_ACCEPTED = 0
MSG_DENIED   = 1
reply_stat = {
    0: 'MSG_ACCEPTED',
    1: 'MSG_DENIED',
}

# accept_stat
SUCCESS       = 0  # RPC executed successfully
PROG_UNAVAIL  = 1  # remote hasn't exported program
PROG_MISMATCH = 2  # remote can't support version #
PROC_UNAVAIL  = 3  # program can't support procedure
GARBAGE_ARGS  = 4  # procedure can't decode params
SYSTEM_ERR    = 5  # e.g. memory allocation failure
accept_stat = {
    0: 'SUCCESS',
    1: 'PROG_UNAVAIL',
    2: 'PROG_MISMATCH',
    3: 'PROC_UNAVAIL',
    4: 'GARBAGE_ARGS',
    5: 'SYSTEM_ERR',
}

# reject_stat
RPC_MISMATCH = 0, # RPC version number != 2
AUTH_ERROR   = 1  # remote can't authenticate caller
reject_stat = {
    0: 'RPC_MISMATCH',
    1: 'AUTH_ERROR',
}

# auth_stat
AUTH_OK                 = 0  # success
                             # failed at remote end
AUTH_BADCRED            = 1  # bad credential (seal broken)
AUTH_REJECTEDCRED       = 2  # client must begin new session
AUTH_BADVERF            = 3  # bad verifier (seal broken)
AUTH_REJECTEDVERF       = 4  # verifier expired or replayed
AUTH_TOOWEAK            = 5  # rejected for security reasons
                             # failed locally
AUTH_INVALIDRESP        = 6  # bogus response verifier
AUTH_FAILED             = 7  # reason unknown
                             # AUTH_KERB errors; deprecated.  See [RFC2695]
AUTH_KERB_GENERIC       = 8  # kerberos generic error
AUTH_TIMEEXPIRE         = 9  # time of credential expired
AUTH_TKT_FILE          = 10  # problem with ticket file
AUTH_DECODE            = 11  # can't decode authenticator
AUTH_NET_ADDR          = 12  # wrong net address in ticket
                             # RPCSEC_GSS GSS related errors
RPCSEC_GSS_CREDPROBLEM = 13  # no credentials for user
RPCSEC_GSS_CTXPROBLEM  = 14  # problem with context
auth_stat = {
     0: 'AUTH_OK',
     1: 'AUTH_BADCRED',
     2: 'AUTH_REJECTEDCRED',
     3: 'AUTH_BADVERF',
     4: 'AUTH_REJECTEDVERF',
     5: 'AUTH_TOOWEAK',
     6: 'AUTH_INVALIDRESP',
     7: 'AUTH_FAILED',
     8: 'AUTH_KERB_GENERIC',
     9: 'AUTH_TIMEEXPIRE',
    10: 'AUTH_TKT_FILE',
    11: 'AUTH_DECODE',
    12: 'AUTH_NET_ADDR',
    13: 'RPCSEC_GSS_CREDPROBLEM',
    14: 'RPCSEC_GSS_CTXPROBLEM',
}

# authentication flavor numbers
AUTH_NONE  = 0  # no authentication, see RFC 1831
                # a.k.a. AUTH_NULL
AUTH_SYS   = 1  # unix style (uid+gids), RFC 1831
                # a.k.a. AUTH_UNIX
AUTH_SHORT = 2  # short hand unix style, RFC 1831
AUTH_DH    = 3  # des style (encrypted timestamp)
                # a.k.a. AUTH_DES, see RFC 2695
AUTH_KERB  = 4  # kerberos auth, see RFC 2695
AUTH_RSA   = 5  # RSA authentication
RPCSEC_GSS = 6  # GSS-based RPC security for auth,
                # integrity and privacy, RPC 5403
auth_flavor = {
    0: 'AUTH_NONE',
    1: 'AUTH_SYS',
    2: 'AUTH_SHORT',
    3: 'AUTH_DH',
    4: 'AUTH_KERB',
    5: 'AUTH_RSA',
    6: 'RPCSEC_GSS',
}
