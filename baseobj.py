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
Base object

Base class so objects will inherit the methods which provide the string
representation of the object and methods to change the verbosity of such
string representation. It also includes a simple debug printing and logging
mechanism including methods to change the debug verbosity level and methods
to add debug levels.
"""
import re
import nfstest_config as c
from pprint import pformat,pprint

# Module constants
__author__    = 'Jorge Mora (%s)' % c.NFSTEST_AUTHOR_EMAIL
__version__   = '1.0.1'
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"

# Module variables
_dindent = 0
_dlevel = 0
_rlevel = 0
_logfh = None
# Simple verbose level names
_debug_map = {
    'none':  0,
    'info':  1,    # Display info only
    'debug': 0xFF, # Display info and all debug messages 0x02-0x80
    'all':   0xFFFFFFFF, # Display all messages
}
# Debug display prefixes
_debug_prefix = {
    0x001: 'INFO: ',
}

def _init_debug():
    """Define all debug flags"""
    for i in xrange(7):
        dbg = 'dbg%d' % (i+1)
        _debug_map[dbg] = (2 << i)
        _debug_prefix[(2 << i)] = dbg.upper() + ': '
_init_debug()

class BaseObj(object):
    """Base class so objects will inherit the methods which provide the string
       representation of the object and a simple debug printing and logging
       mechanism.
    """
    def __init__(self, *kwts, **kwds):
        """Constructor

           Initialize object's private data according to the arguments given

           Examples:
               # Named arguments
               x = BaseObj(a=1, b=2)

               # Dictionary argument
               x = BaseObj({'a':1, 'b':2})

               # Tuple arguments: first for keys and second for the values
               x = BaseObj(['a', 'b'], [1, 2])

               # All of the above will create an object having two attributes:
               x.a = 1 and x.b = 2
        """
        keys = None
        for item in kwts:
            if type(item) == dict:
                self.__dict__.update(item)
            elif type(item) == list or type(item) == tuple:
                if keys is None:
                    keys = item
                else:
                    self.__dict__.update(zip(keys,item))
                    keys = None
        # Process named arguments: x = BaseObj(a=1, b=2)
        self.__dict__.update(kwds)

    def __repr__(self):
        """String representation of object

           The representation depends on the verbose level set by debug_repr().
           If set to 0 the generic object representation is returned, else
           the representation of the object includes all object attributes
           and their values with proper indentation.
        """
        global _rlevel
        if _rlevel == 0:
            # Return generic object representation
            return object.__repr__(self)

        # Representation of object with proper indentation
        indent = ' ' * 4
        out = self.__class__.__name__ + "(\n"
        itemlist = getattr(self, '_itemlist', None)
        if itemlist is None:
            itemlist = sorted(self.__dict__.iterkeys())
        for key in itemlist:
            if key[0] != '_':
                val = self.__dict__.get(key, None)
                if val != None:
                    value = pformat(val)
                    out += "    %s = %s,\n" % (key, value.replace("\n", "\n"+indent))
                else:
                    out += "    %s = None,\n" % key
        out += ")"
        return out
    __str__ = __repr__

    @staticmethod
    def debug_repr(level=None):
        """Return or set verbose level of object's string representation.
           When setting the verbose level, return the verbose level before
           setting it.

           level:
               Level of verbosity to set
        """
        global _rlevel
        ret = _rlevel
        if level is not None:
            _rlevel = level
        return ret

    def debug_level(self, level=0):
        """Set debug level mask.

           level:
               Level to set. This could be a number or a string expression
               of names defined by debug_map()

           Examples:
               # Set level
               x.debug_level(0xFF)

               # Set level using expression
               x.debug_level('all')
               x.debug_level('debug ^ 1')
        """
        global _dlevel
        if type(level) == str:
            # Convert named verbose levels to a number
            # -- Get a list of all named verbose levels
            for item in sorted(set(re.split('\W+', level))):
                if len(item) > 0:
                    if item in _debug_map:
                        # Replace all occurrences of named verbose level
                        # to its corresponding numeric value
                        level = re.sub(r'\b' + item + r'\b', hex(_debug_map[item]), level)
                    else:
                        try:
                            # Find out if verbose is a number
                            # (decimal, hex, octal, ...)
                            tmp = int(item, 0)
                        except:
                            raise Exception("Unknown debug level [%s]" % item)
            # Evaluate the whole expression
            _dlevel = eval(level)
        else:
            # Already a number
            _dlevel = level
        return _dlevel

    @staticmethod
    def debug_map(bitmap, name='', disp=''):
        """Add a debug mapping.

           Generic debug levels map
             <bitmap>  <name>  <disp prefix>
              0x000    'none'
              0x001    'info'  'INFO: ' # Display info messages only
              0x0FF    'debug' 'DBG:  ' # Display info and all debug messages (0x02-0x80)
             >0x100    user defined verbose levels
        """
        if name:
            _debug_map[name] = bitmap
        if disp:
            _debug_prefix[bitmap] = disp

    @staticmethod
    def dindent(indent):
        """Set global indentation."""
        global _dindent
        _dindent = indent

    def open_log(self, logfile):
        """Open log file."""
        global _logfh
        self.close_log()
        _logfh = open(logfile, "w")

    def close_log(self):
        """Close log file."""
        global _logfh
        if _logfh != None:
            _logfh.close()
            _logfh = None

    @staticmethod
    def write_log(data):
        """Write data to log file."""
        if _logfh != None:
            _logfh.write(data + "\n")

    def dprint(self, level, msg, indent=0):
        """Print debug message if level is allowed by the verbose level
           given in debug_level().
        """
        ret = ''
        if level is None:
            return
        if type(level) == str:
            level = _debug_map[level.lower()]
        if level & _dlevel:
            # Add display prefix only if msg is not an empty string
            if len(msg):
                # Find the right display prefix
                prefix = ' ' * _dindent
                for bitmap in sorted(_debug_prefix):
                    if level & bitmap:
                        prefix += _debug_prefix[bitmap]
                        break
                # Add display prefix to the message
                sp = ' ' * indent
                ret = prefix + sp + msg
                indent += len(prefix)
            if indent > 0:
                sp = ' ' * indent
                ret = ret.replace("\n", "\n"+sp)
            print ret
            self.write_log(ret)

