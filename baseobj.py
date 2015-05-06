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

Base class so objects will inherit the methods providing the string
representation of the object and methods to change the verbosity of such
string representation. It also includes a simple debug printing and logging
mechanism including methods to change the debug verbosity level and methods
to add debug levels.
"""
import re
import nfstest_config as c
from pprint import pformat
from formatstr import FormatStr

# Module constants
__author__    = 'Jorge Mora (%s)' % c.NFSTEST_AUTHOR_EMAIL
__version__   = '1.0.3'
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"

# Module variables
_dindent = ""
_sindent = "    "
_dlevel = 0
_rlevel = 1
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

class BaseObj(FormatStr):
    """Base class so objects will inherit the methods providing the string
       representation of the object and a simple debug printing and logging
       mechanism.

       Usage:
           from baseobj import BaseObj

           # Named arguments
           x = BaseObj(a=1, b=2)

           # Dictionary argument
           x = BaseObj({'a':1, 'b':2})

           # Tuple arguments: first for keys and second for the values
           x = BaseObj(['a', 'b'], [1, 2])

           # All of the above will create an object having two attributes:
           x.a = 1 and x.b = 2

           # Add attribute name, this will be the only attribute to be displayed
           x.set_attrlist("a")

           # Add list of attribute names to be displayed in that order
           x.set_attrlist(["a", "b"])

           # Set the comparison attribute so x == x.a is True
           x.set_eqattr("a")

           # Set verbose level of object's string representation
           x.debug_repr(level)

           # Set level mask to display all debug messages matching mask
           x.debug_level(0xFF)

           # Add a debug mapping for mask 0x100
           x.debug_map(0x100, 'opts', "OPTS: ")

           # Set global indentation to 4 spaces for dprint
           x.dindent(4)

           # Set global indentation to 4 spaces for displaying objects
           x.sindent(4)

           # Open log file
           x.open_log(logfile)

           # Close log file
           x.close_log()

           # Write data to log file
           x.write_log(data)

           # Print debug message only if OPTS bitmap matches the current
           # debug level mask
           x.dprint("OPTS", "This is an OPTS debug message")
    """
    # Class attributes
    _attrlist = None # List of attributes to display in order
    _eqattr   = None # Comparison attribute

    def __init__(self, *kwts, **kwds):
        """Constructor

           Initialize object's private data according to the arguments given.
           Arguments can be given as positional, named arguments or a
           combination of both.
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

    def __eq__(self, other):
        """Comparison method: this object is treated like the attribute
           defined by set_eqattr()
        """
        if self._eqattr is None:
            # Compare object
            return id(other) == id(self)
        else:
            # Compare defined attribute
            return other == getattr(self, self._eqattr)

    def __ne__(self, other):
        """Comparison method: this object is treated like the attribute
           defined by set_eqattr()
        """
        return not self.__eq__(other)

    def __repr__(self):
        """String representation of object

           The representation depends on the verbose level set by debug_repr().
           If set to 0 the generic object representation is returned, else
           the representation of the object includes all object attributes
           and their values with proper indentation.
        """
        return self._str_repr(True)

    def __str__(self):
        """Informal string representation of object

           The representation depends on the verbose level set by debug_repr().
           If set to 0 the generic object representation is returned, else
           the representation of the object includes all object attributes
           and their values.
        """
        return self._str_repr()

    def _str_repr(self, isrepr=False):
        """String representation of object"""
        global _rlevel
        if _rlevel == 0:
            # Return generic object representation
            if isrepr:
                return super(BaseObj, self).__repr__()
            else:
                return super(BaseObj, self).__str__()

        # Representation of object with proper indentation
        out = []
        if self._attrlist is None:
            attrlist = sorted(self.__dict__.keys())
        else:
            attrlist = self._attrlist
        for key in attrlist:
            if key[0] != '_':
                val = getattr(self, key, None)
                if val != None:
                    if isrepr:
                        value = pformat(val)
                        out.append("%s%s = %s,\n" % (_sindent, key, value.replace("\n", "\n"+_sindent)))
                    else:
                        out.append("%s=%s" % (key, self._str_value(val)))
        name = self.__class__.__name__
        if isrepr:
            joinstr = ""
            if len(out) > 0:
                out.insert(0, "\n")
        else:
            joinstr = ", "
        return "%s(%s)" % (name, joinstr.join(out))

    def _str_value(self, value):
        """Format value"""
        if isinstance(value, list) or isinstance(value, tuple):
            # Display list or tuple
            out = []
            for item in value:
                out.append(self._str_value(item))
            return '[' + ', '.join(out) + ']'
        elif isinstance(value, dict):
            # Display dictionary
            out = []
            for key,val in value.iteritems():
                out.append(str(key) + ": " + self._str_value(val))
            return '{' + ', '.join(out) + '}'
        elif type(value) == int or type(value) == long or type(value) == str:
            return repr(value)
        else:
            return str(value)

    def set_attrlist(self, attr):
        """Add list of attribute names in object to display by str() or repr()

           attr:
               Name or list of names to add to the list of attribute names
               to display
        """
        if self._attrlist is None:
            self._attrlist = []
        if isinstance(attr, list):
            # Add given list of items
            self._attrlist += attr
        else:
            # Add a single item
            self._attrlist.append(attr)

    def set_eqattr(self, attr):
        """Set the comparison attribute

           attr:
               Attribute to use for object comparison

           Examples:
               x = BaseObj(a=1, b=2)
               x.set_eqattr("a")
               x == 1 will return True, the same as x.a == 1
        """
        self._eqattr = attr

    @staticmethod
    def debug_repr(level=None):
        """Return or set verbose level of object's string representation.
           When setting the verbose level, return the verbose level before
           setting it.

           level:
               Level of verbosity to set

           Examples:
               # Set verbose level to its minimal object representation
               x.debug_repr(0)

               # Object representation is a bit more verbose
               x.debug_repr(1)

               # Object representation is a lot more verbose
               x.debug_repr(2)
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
    def dindent(indent=None):
        """Set global dprint indentation."""
        global _dindent
        if indent is not None:
            _dindent = " " * indent
        return _dindent

    @staticmethod
    def sindent(indent=None):
        """Set global object indentation."""
        global _sindent
        if indent is not None:
            _sindent = " " * indent
        return _sindent

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

    @staticmethod
    def flush_log():
        """Flush data to log file."""
        if _logfh != None:
            _logfh.flush()

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
                prefix = _dindent
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
