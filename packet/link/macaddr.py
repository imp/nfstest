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
MacAddr module

Create an object to represent a MAC address. A MAC address is given either
by a series of hexadecimal numbers or using the ":" notation. It provides
a mechanism for comparing this object with a regular string.
"""
import nfstest_config as c

# Module constants
__author__    = 'Jorge Mora (%s)' % c.NFSTEST_AUTHOR_EMAIL
__version__   = '1.0.1'
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"

class MacAddr(str):
    """MacAddr address object

       Usage:
           from packet.link.macaddr import MacAddr

           mac = MacAddr('E4CE8F589FF4')

       The following expressions are equivalent:
           mac == 'E4CE8F589FF4'
           mac == 'e4ce8f589ff4'
           mac == 'e4:ce:8f:58:9f:f4'
    """
    @staticmethod
    def _convert(mac):
        """Convert string into a persistent representation of a MAC address."""
        if mac != None:
            mac = mac.lower()
            if len(mac) == 12:
                # Add ":" to the string
                t = iter(mac)
                mac = ':'.join(a+b for a,b in zip(t, t))
        return mac

    def __new__(cls, mac):
        """Create new instance by converting input string into a persistent
           representation of a MAC address.
        """
        return super(MacAddr, cls).__new__(cls, MacAddr._convert(mac))

    def __eq__(self, other):
        """Compare two MAC addresses and return True if both are equal."""
        return str(self) == self._convert(other)

    def __ne__(self, other):
        """Compare two MAC addresses and return False if both are equal."""
        return not self.__eq__(other)

if __name__ == '__main__':
    # Self test of module
    mac = MacAddr('E4CE8F589FF4')
    macstr = "%s" % mac
    macrpr = "%r" % mac
    ntests = 6

    tcount = 0
    if mac == 'E4CE8F589FF4':
        tcount += 1
    if mac == 'e4ce8f589ff4':
        tcount += 1
    if mac == 'E4:CE:8F:58:9F:F4':
        tcount += 1
    if mac == 'e4:ce:8f:58:9f:f4':
        tcount += 1
    if macstr == 'e4:ce:8f:58:9f:f4':
        tcount += 1
    if macrpr == "'e4:ce:8f:58:9f:f4'":
        tcount += 1

    if tcount == ntests:
        print "All tests passed!"
        exit(0)
    else:
        print "%d tests failed" % (ntests-tcount)
        exit(1)
