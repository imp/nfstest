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
Unpack module

Provides the object for managing and unpacking raw data from a working buffer.
"""
import struct
import nfstest_config as c

# Module constants
__author__    = 'Jorge Mora (%s)' % c.NFSTEST_AUTHOR_EMAIL
__version__   = '1.0.1'
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"

class Unpack(object):
    """Unpack object

       Usage:
           from packet.unpack import Unpack

           x = Unpack(buffer)

           # Get the 32 bytes from the working buffer
           data = x.rawdata(32)

           # Unpack an 'unsigned short' (2 bytes)
           short_int = x.unpack(2, 'H')[0]
    """
    def __init__(self, data):
        """Constructor

           Initialize object's private data.

           data:
               Raw packet data
        """
        self.data = data

    def rawdata(self, size):
        """Get the number of bytes given from the working buffer."""
        buf = self.data[0:size]
        self.data = self.data[size:]
        return buf

    def unpack(self, size, fmt):
        """Get the number of bytes given from the working buffer and process
           it according to the given format.
           Return a tuple of unpack items, see struct.unpack.
        """
        return struct.unpack('!'+fmt, self.rawdata(size))

