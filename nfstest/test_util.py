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
Test utilities module

Provides a set of tools for testing either the NFS client or the NFS server,
most of the functionality is focused mainly on testing the client.
These tools include the following:

    - Process command line arguments
    - Provide functionality for PASS/FAIL
    - Provide test grouping functionality
    - Provide multiple client support
    - Logging mechanism
    - Debug info control
    - Mount/Unmount control
    - Create files/directories
    - Provide mechanism to start a packet trace
    - Provide mechanism to simulate a network partition
    - Support for pNFS testing

In order to use some of the functionality available, the user id in all the
client hosts must have access to run commands as root using the 'sudo' command
without the need for a password, this includes the host where the test is being
executed. This is used to run commands like 'mount' and 'umount'. Furthermore,
the user id must be able to ssh to remote hosts without the need for a password
if test requires the use of multiple clients.

Network partition is simulated by the use of 'iptables', please be advised
that after every test run the iptables is flushed and reset so any rules
previously setup will be lost. Currently, there is no mechanism to restore
the iptables rules to their original state.
"""
import os
import re
import sys
import time
import fcntl
import struct
import inspect
import textwrap
from host import Host
import nfstest_config as c
from baseobj import BaseObj
from nfs_util import NFSUtil
from optparse import OptionParser, IndentedHelpFormatter

# Module constants
__author__    = 'Jorge Mora (%s)' % c.NFSTEST_AUTHOR_EMAIL
__version__   = '1.1'
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"

PASS = 0
HEAD = 1
INFO = 2
FAIL = -1
WARN = -2
BUG  = -3
IGNR = -4

_isatty = os.isatty(1)

_test_map = {
    HEAD: "\n*** ",
    INFO: "    ",
    PASS: "    PASS: ",
    FAIL: "    FAIL: ",
    WARN: "    WARN: ",
    BUG:  "    BUG:  ",
    IGNR: "    IGNR: ",
}

# Provide colors on PASS, FAIL, WARN messages
_test_map_c = {
    HEAD: "\n*** ",
    INFO: "    ",
    PASS: "    \033[32mPASS\033[m: ",
    FAIL: "    \033[31mFAIL\033[m: ",
    WARN: "    \033[33mWARN\033[m: ",
    BUG:  "    \033[33mBUG\033[m:  ",
    IGNR: "    \033[33mIGNR\033[m: ",
}

_tverbose_map = {'group': 0, 'normal': 1, 'verbose': 2, '0':0, '1':1, '2':2}
_rtverbose_map = dict(zip(_tverbose_map.values(),_tverbose_map))

BaseObj.debug_map(0x100, 'opts', "OPTS: ")

class TestUtil(NFSUtil):
    """TestUtil object

       TestUtil() -> New server object

       Usage:
           x = TestUtil()

           # Process command line options
           x.scan_options()

           # Start packet trace using tcpdump
           x.trace_start()

           # Mount volume
           x.mount()

           # Create file
           x.create_file()

           # Unmount volume
           x.umount()

           # Stop packet trace
           x.trace_stop()

           # Exit script
           x.exit()
    """
    def __init__(self, **kwargs):
        """Constructor

           Initialize object's private data.

           sid:
               Test script ID [default: '']
               This is used to have options targeted for a given ID without
               including these options in any other test script.
           usage:
               Usage string [default: '']
           testnames:
               List of testnames [default: []]
               When this list is not empty, the --runtest option is enabled and
               test scripts should use the run_tests() method to run all the
               tests. Test script should have methods named as <testname>_test.

           Example:
               x = TestUtil(testnames=['basic', 'lock'])

               # The following methods should exist:
               x.basic_test()
               x.lock_test()
        """
        self.sid       = kwargs.pop('sid', "")
        self.usage     = kwargs.pop('usage', '')
        self.testnames = kwargs.pop('testnames', [])
        self.progname = os.path.basename(sys.argv[0])
        self.testname = ""
        if self.progname[-3:] == '.py':
            # Remove extension
            self.progname = self.progname[:-3]
        self._name = None
        self.tverbose = 1
        self._bugmsgs = []
        self.ignore = False
        self.bugmsgs = None
        self.nocleanup = True
        self.test_time = [time.time()]
        self._fileopt = True
        self.remove_list = []
        self.fileidx = 1
        self.diridx = 1
        self.logidx = 1
        self.files = []
        self.dirs = []
        self.abshash = {}
        self.test_msgs = []
        self._msg_count = {}
        self._reset_files()
        self._runtest = True
        self.createtraces = False

        for tid in _test_map:
            self._msg_count[tid] = 0
        self.dindent(4)

        self.optfiles = []
        self.testopts = {}
        NFSUtil.__init__(self)
        self._init_options()

    def __del__(self):
        """Destructor

           Gracefully stop the packet trace, cleanup files, unmount volume,
           and reset network.
        """
        self.debug_repr(0)
        self._tverbose()
        self._print_msg("")
        self.dprint('DBG7', "Calling %s() destructor" % self.__class__.__name__)
        self.trace_stop()
        self.cleanup()
        # Call base destructor
        NFSUtil.__del__(self)

        if len(self.test_msgs) > 0:
            if getattr(self, 'logfile', None):
                print "\nLogfile: %s" % self.logfile
            msg = "%d tests%s" % self._total_counts(self._msg_count)
            self.write_log("\n" + msg)
            if self._msg_count[FAIL] > 0:
                msg = "\033[31m" + msg + "\033[m" if _isatty else msg
            elif self._msg_count[WARN] > 0:
                msg = "\033[33m" + msg + "\033[m" if _isatty else msg
            else:
                msg = "\033[32m" + msg + "\033[m" if _isatty else msg
            print "\n" + msg
        self.total_time = time.time() - self.test_time[0]
        total_str = "\nTotal time: %s" % self._print_time(self.total_time)
        self.write_log(total_str)
        print total_str
        self.close_log()

    def _verify_testnames(self):
        """Process --runtest option."""
        if not hasattr(self, 'runtest'):
            return
        if self.runtest == 'all':
            self.testlist = self.testnames
        else:
            if self.runtest[0] == '^':
                # List is negated tests -- do not run the tests listed
                runtest = self.runtest.replace('^', '', 1)
                negtestlist = self.str_list(runtest)
                self.testlist = self.testnames
                for testname in negtestlist:
                    if testname in self.testlist:
                        self.testlist.remove(testname)
                    else:
                        self.opts.error("invalid value given --runtest=%s" % self.runtest)
            else:
                self.testlist = self.str_list(self.runtest)
            if self.testlist is None:
                self.opts.error("invalid value given --runtest=%s" % self.runtest)
        msg = ''
        for testname in self.testlist:
            if testname not in self.testnames:
                msg += "Invalid test name:    %s\n" % testname
            elif not hasattr(self, testname + '_test'):
                msg += "Test not implemented: %s\n" % testname
            else:
                tname = testname + '_test'
        if len(msg) > 0:
            self.config(msg)

    def _init_options(self):
        """Initialize command line options parsing and definitions."""
        self.opts = OptionParser("%prog [options]", formatter = IndentedHelpFormatter(2, 25), version = "%prog " + __version__)
        self.opts.add_option("-f", "--file", default="", help="Options file")
        self.opts.add_option("-s", "--server", default=self.server, help="Server name or IP address")
        self.opts.add_option("-p", "--port", type="int", default=self.port, help="NFS server port [default: %default]")
        self.opts.add_option("--proto", default=self.proto, help="NFS protocol name [default: '%default']")
        self.opts.add_option("--sec", default=self.sec, help="Security flavor [default: '%default']")
        self.opts.add_option("--nfsversion", type="int", default=self.nfsversion, help="NFS version [default: %default]")
        self.opts.add_option("--minorversion", type="int", default=self.minorversion, help="Minor version [default: %default]")
        self.opts.add_option("-e", "--export", default=self.export, help="Exported file system to mount [default: '%default']")
        self.opts.add_option("-m", "--mtpoint", default=self.mtpoint, help="Mount point [default: '%default']")
        self.opts.add_option("--datadir", default=self.datadir, help="Data directory where files are created [default: '%default']")
        self.opts.add_option("-o", "--mtopts", default=self.mtopts, help="Mount options [default: '%default']")
        self.opts.add_option("-i", "--interface", default=None, help="Device interface [default: '%default']")
        self.opts.add_option("-v", "--verbose", default="none", help="Verbose level [default: '%default']")
        self.opts.add_option("--nocleanup", action="store_true", default=False, help="Do not cleanup")
        self.opts.add_option("--rmtraces", action="store_true", default=False, help="Remove trace files [default: remove trace files if no errors]")
        self.opts.add_option("--keeptraces", action="store_true", default=False, help="Do not remove any trace files [default: remove trace files if no errors]")
        self.opts.add_option("--createtraces", action="store_true", default=False, help="Create a packet trace for each test [default: %default]")
        self.opts.add_option("--createlog", action="store_true", default=False, help="Create log file")
        self.opts.add_option("--bugmsgs", default=self.bugmsgs, help="File containing test messages to mark as bugs if they failed")
        self.opts.add_option("--ignore", action="store_true", default=self.ignore, help="Ignore all bugs given by bugmsgs")
        self.opts.add_option("--nomount", action="store_true", default=self.nomount, help="Do not mount server")
        self.opts.add_option("--basename", default='', help="Base name for all files and logs [default: automatically generated]")
        self.opts.add_option("--tverbose", default=_rtverbose_map[self.tverbose], help="Verbose level for test messages [default: '%default']")
        self.opts.add_option("--filesize", type="int", default=65536, help="File size to use for test files [default: %default]")
        self.opts.add_option("--nfiles", type="int", default=2, help="Number of files to create [default: %default]")
        self.opts.add_option("--rsize", type="int", default=4096, help="Read size to use when reading files [default: %default]")
        self.opts.add_option("--wsize", type="int", default=4096, help="Write size to use when writing files [default: %default]")
        self.opts.add_option("--iodelay", type="float", default=0.1, help="Seconds to delay I/O operations [default: %default]")
        self.opts.add_option("--trcdelay", type="float", default=0.0, help="Seconds to delay before stopping packet trace [default: %default]")
        self.opts.add_option("--offset-delta", type="int", default=4096, help="Read/Write offset delta [default: %default]")
        self.opts.add_option("--warnings", action="store_true", default=False, help="Display warnings")
        self.opts.add_option("--nfsdebug", default=self.nfsdebug, help="Set NFS kernel debug flags and save log messages [default: '%default']")
        self.opts.add_option("--rpcdebug", default=self.rpcdebug, help="Set RPC kernel debug flags and save log messages [default: '%default']")
        self.opts.add_option("--sudo", default=self.sudo, help="Full path of binary for sudo [default: '%default']")
        self.opts.add_option("--tcpdump", default=self.tcpdump, help="Full path of binary for tcpdump [default: '%default']")
        self.opts.add_option("--tbsize", type="int", default=self.tbsize, help="Capture buffer size for tcpdump [default: '%default']")
        self.opts.add_option("--iptables", default=self.iptables, help="Full path of binary for iptables [default: '%default']")
        self.opts.add_option("--messages", default=self.messages, help="Full path of log messages file [default: '%default']")
        self.opts.add_option("--tmpdir", default=self.tmpdir, help="Temporary directory [default: '%default']")
        usage = self.usage
        if len(self.testnames) > 0:
            self.opts.add_option("--runtest", default='all', help="Comma separated list of tests to run [default: '%default']")
            if len(usage) == 0:
                usage = "%prog [options]"
            usage += "\n\nAvailable tests:"
            for tname in self.testnames:
                desc = getattr(self, tname+'_test').__doc__
                if desc != None:
                    lines = desc.lstrip().split('\n')
                    desc = lines.pop(0)
                    if len(desc) > 0:
                        desc += '\n'
                    desc += textwrap.dedent("\n".join(lines))
                    desc = desc.replace("\n", "\n        ")
                usage += "\n    %s:\n        %s" % (tname, desc)
            usage = usage.rstrip()
        if len(usage) > 0:
            self.opts.set_usage(usage)
        self._cmd_line = " ".join(sys.argv)
        self._opts = {}

    @staticmethod
    def str_list(value, type=str, sep=","):
        """Return a list of <type> elements from the comma separated string."""
        slist = []
        try:
            for item in value.replace(' ', '').split(sep):
                if len(item) > 0:
                    if type == int:
                        val = int(item)
                    elif type == float:
                        val = float(item)
                    else:
                        val = item
                    slist.append(val)
                else:
                    slist.append(None)
        except:
            return
        return slist

    @staticmethod
    def get_list(value, hash, type=str):
        """Return a list of elements from the comma separated string.
           Validate and translate these elements using the input dictionary
           'hash' where every element in the string is the key of 'hash'
           and its value is appended to the returned list.
        """
        rlist = []
        slist = TestUtil.str_list(value)
        if slist is None:
            return
        for i_item in slist:
            item = i_item.lower()
            if hash.has_key(item):
                rlist.append(hash[item])
            else:
                return
        return rlist

    def str_nfs(self, **kwargs):
        """Return the NFS string according to the given version and minorversion.

           version:
               NFS version [default: --nfsversion option]
           minorversion:
               NFS minor version [default: --minorversion option]
        """
        nfsversion   = kwargs.pop("version",      self.nfsversion)
        minorversion = kwargs.pop("minorversion", self.minorversion)
        return "NFSv%d%s" % (nfsversion, ".%d" % minorversion if minorversion else "")

    def scan_options(self):
        """Process command line options.

           Process all the options in the file given by '--file', then the
           ones in the command line. This allows for command line options
           to over write options given in the file.

           Format of options file:
               # For options expecting a value
               <option_name> = <value>

               # For boolean (flag) options
               <option_name>

           Process options files and make sure not to process the same file
           twice, this is used for the case where HOMECFG and CWDCFG are the
           same, more specifically when environment variable HOME is not
           defined. Also, the precedence order is defined as follows:
             1. options given in command line
             2. options given in file specified by the -f|--file option
             3. options given in file specified by ./.nfstest
             4. options given in file specified by $HOME/.nfstest
             5. options given in file specified by /etc/nfstest

           NOTE:
             Must use the long name of the option (--<option_name>) in the file.
        """
        opts, args = self.opts.parse_args()
        if self._fileopt:
            # Find which options files exist and make sure not to process the
            # same file twice, this is used for the case where HOMECFG and
            # CWDCFG are the same, more specifically when environment variable
            # HOME is not defined.
            ofiles = {}
            self.optfiles = [[opts.file, []]] if opts.file else []
            for optfile in [c.NFSTEST_CWDCFG, c.NFSTEST_HOMECFG, c.NFSTEST_CONFIG]:
                if ofiles.get(optfile) is None:
                    # Add file if it has not been added yet
                    ofiles[optfile] = 1
                    if os.path.exists(optfile):
                        self.optfiles.insert(0, [optfile, []])
        if self.optfiles and self._fileopt:
            # Options are given in any of the options files
            self._fileopt = False # Only process the '--file' option once
            argv = []
            for (optfile, lines) in self.optfiles:
                bcount = 0
                islist = False
                idblock = None
                testblock = None
                for optline in open(optfile, 'r'):
                    line = optline.strip()
                    if len(line) == 0 or line[0] == '#':
                        # Skip comments
                        continue
                    # Save current line of file for displaying purposes
                    lines.append(optline.rstrip())
                    # Process valid options, option name and value is separated
                    # by spaces or an equal sign
                    m = re.search("([^=\s]+)\s*=?\s*(.*)", line)
                    name = m.group(1)
                    name = name.strip()
                    value = m.group(2)
                    # Add current option to argument list as if the option was
                    # given on the command line to be able to use parse_args()
                    # again to process all options given in the options files
                    if name in ["}", "]"]:
                        # End of block, make sure to close an opened testblock
                        # first before closing an opened idblock
                        bcount -= 1
                        if testblock is not None:
                            testblock = None
                        else:
                            idblock = None
                    elif len(value) > 0:
                        value = value.strip()
                        if value in ["{", "["]:
                            # Start of block, make sure to open an idblock
                            # first before opening a testblock
                            islist = True if value == "[" else False
                            bcount += 1
                            if idblock is None:
                                idblock = name
                            elif idblock == self.sid:
                                # Open a testblock only if testblock is located
                                # inside an idblock correspondig to script ID
                                testblock = name
                                if self.testopts.get(name) is None:
                                    # Initialize testblock only if it has not
                                    # been initialized, this allows for multiple
                                    # definitions of the same testblock
                                    if islist:
                                        self.testopts[name] = []
                                    else:
                                        self.testopts[name] = {}
                        elif testblock is not None:
                            # Inside a testblock, add name/value to testblock
                            # dictionary
                            if islist:
                                self.testopts[testblock].append(line)
                            else:
                                self.testopts[testblock][name] = value
                        elif idblock is None or idblock == self.sid:
                            # Include all general options and options given
                            # by the block specified by the correct script ID
                            argv.append("--%s=%s" % (name, value))
                    elif testblock is not None:
                        # Inside a testblock, add name to testblock dictionary
                        if islist:
                            self.testopts[testblock].append(name)
                        else:
                            self.testopts[testblock][name] = True
                    elif idblock is None or (idblock == self.sid and testblock is None):
                        # Include all general options and options given
                        # by the block specified by the correct script ID
                        argv.append("--%s" % name)
                if bcount != 0:
                    self.config("Missing closing brace in options file '%s'" % optfile)
            # Add all other options in the command line, make sure all options
            # explicitly given in the command line have higher precedence than
            # options given in any of the options files
            sys.argv[1:] = argv + sys.argv[1:]
            # Process the command line arguments again to overwrite options
            # explicitly given in the command line in conjunction with the
            # --file option
            self.scan_options()
        else:
            try:
                # Set verbose level mask
                self.debug_level(opts.verbose)
            except Exception, e:
                self.opts.error("Invalid verbose level <%s>: %s" % (opts.verbose, e))

            if opts.createlog and len(opts.basename) == 0:
                self.logfile = "%s/%s.log" % (opts.tmpdir, self.get_name())
                self.open_log(self.logfile)

            _lines = [self._cmd_line]
            for (optfile, lines) in self.optfiles:
                # Add the content of each option file that has been processed
                if len(lines) > 0:
                    _lines.append("")
                    _lines.append("Contents of options file [%s]:" % optfile)
                    _lines += lines
            self.dprint('OPTS', "\n".join(_lines))
            self.dprint('OPTS', "")
            for key in sorted(vars(opts)):
                value = getattr(opts,key)
                self._opts[key] = value
                line = "%s = %s" % (key, value)
                self.dprint('OPTS', line)
            self.dprint('OPTS', "")

            # Display system information
            self.dprint('INFO', "SYSTEM: %s" % " ".join(os.uname()))

            # Process all command line arguments -- all will be part of the
            # objects namespace
            self.__dict__.update(opts.__dict__)
            if not self.server:
                self.opts.error("server option is required")
            self._verify_testnames()
            ipv6 = self.proto[-1] == '6'
            # Get IP address of server
            self.server_ipaddr = self.get_ip_address(host=self.server, ipv6=ipv6)
            # Get IP address of client
            self.client_ipaddr = self.get_ip_address(ipv6=ipv6)
            if self.interface is None:
                out = self.get_route(self.server_ipaddr)
                if out[1] is not None:
                    self.interface = out[1]
                    if out[2] is not None:
                        self.client_ipaddr = out[2]
                else:
                    self.interface = c.NFSTEST_INTERFACE
            self.ipaddr = self.client_ipaddr
            if self.nfsversion < 4:
                self.minorversion = 0

            self.tverbose = _tverbose_map.get(self.tverbose)
            if self.tverbose is None:
                self.opts.error("invalid value for tverbose option")

            if len(self.basename) > 0:
                self._name      = self.basename
                self.nomount    = True
                self.notrace    = True
                self.keeptraces = True
            if self.bugmsgs is not None:
                try:
                    for line in open(self.bugmsgs, 'r'):
                        line = line.strip()
                        if len(line):
                            self._bugmsgs.append(line)
                except Exception as e:
                    self.config("Unable to load bug messages from file '%s': %r" % (self.bugmsgs, e))

            # Set base name for trace files and log message files
            self.tracename = self.get_name()
            self.dbgname = self.get_name()

            # Make sure the network is reset
            self.network_reset()
        return

    def test_options(self, name=None):
        """Get options for the given test name. If the test name is not given
           it is determined by inspecting the stack to find which method is
           calling this method.
        """
        if name is None:
            # Get current testname
            name = self.testname
            if len(name) == 0:
                # Get correct test name by inspecting the stack to find which
                # method is calling this method
                out = inspect.stack()
                name = out[1][3].replace("_test", "")

        # Get options given for this specific test name
        opts = self.testopts.get(name, {})

        # Find if any of the test options are regular expressions
        for key in self.testopts.keys():
            m = re.search("^re\((.*)\)$", key)
            if m:
                # Regular expression specified by re()
                regex = m.group(1)
            else:
                # Find if regular expression is specified by the characters
                # used in the name
                m = re.search("[.^$?+\\\[\]()|]", key)
                regex = key
            if m and re.search(regex, name):
                # Key is specified as a regular expression and matches
                # the test name given, add these options to any options
                # already given by static name match making sure the
                # options given by the exact name are not overwritten
                # by the ones found from a regular expression
                opts = dict(self.testopts[key].items() + opts.items())
        return opts

    def get_logname(self):
        """Get next log file name."""
        logfile = "%s/%s_%d.log" % (self.tmpdir, self.get_name(), self.logidx)
        self.logidx += 1
        return logfile

    def setup(self, nfiles=None):
        """Set up test environment.

           Create nfiles number of files [default: --nfiles option]
        """
        self.dprint('DBG7', "SETUP starts")
        if nfiles is None:
            nfiles = self.nfiles
        need_umount = False
        if not self.mounted and nfiles > 0:
            need_umount = True
            self.umount()
            self.mount()

        # Create files
        for i in range(nfiles):
            self.create_file()

        if need_umount:
            self.umount()
        self.dprint('DBG7', "SETUP done")

    def cleanup(self):
        """Clean up test environment.

           Remove any files created: test files, trace files.
        """
        if self.nocleanup:
            # Nothing to clean up
            return

        self.dprint('DBG7', "CLEANUP starts")
        if not self.keeptraces and (self.rmtraces or self._msg_count[FAIL] == 0):
            for rfile in self.tracefiles:
                try:
                    # Remove trace files as root
                    self.dprint('DBG5', "    Removing trace file [%s]" % rfile)
                    os.system(self.sudo_cmd("rm -f %s" % rfile))
                except:
                    pass

        if not self.mounted and self.remove_list:
            self.mount()
        for rfile in reversed(self.remove_list):
            try:
                if os.path.exists(rfile):
                    if os.path.isfile(rfile):
                        self.dprint('DBG5', "    Removing file [%s]" % rfile)
                        os.unlink(rfile)
                    elif os.path.islink(rfile):
                        self.dprint('DBG5', "    Removing symbolic link [%s]" % rfile)
                        os.unlink(rfile)
                    elif os.path.isdir(rfile):
                        self.dprint('DBG5', "    Removing directory [%s]" % rfile)
                        os.rmdir(rfile)
                    else:
                        self.dprint('DBG5', "    Removing [%s]" % rfile)
                        os.unlink(rfile)
            except:
                pass
        self.dprint('DBG7', "CLEANUP done")

    def run_tests(self, **kwargs):
        """Run all test specified by the --runtest option.

           testnames:
               List of testnames to run [default: all tests given by --testnames]

           All other arguments given are passed to the test methods.
        """
        testnames = kwargs.pop("testnames", self.testlist)
        for name in self.testlist:
            testmethod = name + '_test'
            if name in testnames and hasattr(self, testmethod):
                self._runtest = True
                self._tverbose()
                # Set current testname on object
                self.testname = name
                # Execute test
                getattr(self, testmethod)(**kwargs)

    def _print_msg(self, msg, tid=None):
        """Display message to the screen and to the log file."""
        tidmsg_l = '' if tid is None else _test_map[tid]
        tidmsg_s = _test_map_c.get(tid, tidmsg_l) if _isatty else tidmsg_l
        self.write_log(tidmsg_l + msg)
        print tidmsg_s + msg
        sys.stdout.flush()

    def _print_time(self, sec):
        """Return the given time in the format [[%dh]%dm]%fs."""
        hh = int(sec)/3600
        sec -= 3600.0*hh
        mm = int(sec)/60
        sec -= 60.0*mm
        ret = "%fs" % sec
        if mm > 0:
            ret = "%dm%s" % (mm, ret)
        if hh > 0:
            ret = "%dh%s" % (hh, ret)
        return ret

    def _total_counts(self, gcounts):
        """Internal method to return a string containing how many tests passed
           and how many failed.
        """
        total = gcounts[PASS] + gcounts[FAIL] + gcounts[BUG]
        bugs  = ", %d known bugs" % gcounts[BUG]  if gcounts[BUG] > 0  else ""
        warns = ", %d warnings"   % gcounts[WARN] if gcounts[WARN] > 0 else ""
        tmsg = " (%d passed, %d failed%s%s)" % (gcounts[PASS], gcounts[FAIL], bugs, warns)
        return (total, tmsg)

    def _tverbose(self):
        """Display test group message as a PASS/FAIL including the number
           of tests that passed and failed within this test group when the
           tverbose option is set to 'group' or level 0. It also groups all
           test messages belonging to the same sub-group when the tverbose
           option is set to 'normal' or level 1.
        """
        if self.tverbose == 0 and len(self.test_msgs) > 0:
            # Get the count for each type of message within the
            # current test group
            gcounts = {}
            for tid in _test_map:
                gcounts[tid] = 0
            for item in self.test_msgs[-1]:
                gcounts[item[0]] += 1
            (total, tmsg) = self._total_counts(gcounts)
            # Fail the current test group if at least one of the tests within
            # this group fails
            tid = FAIL if gcounts[FAIL] > 0 else PASS
            # Just add the test group as a single test entity in the total count
            self._msg_count[tid] += 1
            # Just display the test group message with the count of tests
            # that passed and failed within this test group
            msg = self.test_msgs[-1][0][1].replace("\n", "\n          ")
            self._print_msg(msg + tmsg, tid)
            sys.stdout.flush()
        elif self.tverbose == 1 and len(self.test_msgs) > 0:
            # Process all sub-groups within the current test group
            group = self.test_msgs[-1]
            for subroup in group:
                sgtid = subroup[0]
                msg = subroup[1]
                subtests = subroup[2]
                if len(subtests) == 0:
                    # Nothing to process, there are no subtests
                    continue
                # Get the count for each type of message within this
                # test sub-group
                gcounts = {}
                for tid in _test_map:
                    gcounts[tid] = 0
                for subtest in subtests:
                    gcounts[subtest[0]] += 1
                (total, tmsg) = self._total_counts(gcounts)
                # Just add the test sub-group as a single test entity in the
                # total count
                self._msg_count[sgtid] += 1
                # Just display the test group message with the count of tests
                # that passed and failed within this test group
                msg = msg.replace("\n", "\n          ")
                self._print_msg(msg + tmsg, sgtid)
                sys.stdout.flush()
        if self.createtraces:
            self.trace_stop()
        self._test_time()

    def _subgroup_id(self, subgroup, tid):
        """Internal method to return the index of the sub-group message"""
        index = 0
        grpid = None
        # Search the given message in all the sub-group messages
        # within the current group
        group = self.test_msgs[-1]
        for item in group:
            if subgroup == item[1]:
                # Sub-group message found
                grpid = index
                break
            index += 1
        if grpid is None:
            # Sub-group not found, add it
            grpid = len(group)
            group.append([tid, subgroup, []])
        return grpid

    def _test_msg(self, tid, msg, subtest=None, failmsg=None):
        """Common method to display and group test messages."""
        if len(self.test_msgs) == 0 or tid == HEAD:
            # This is the first test message or the start of a group,
            # so process the previous group if any and create a placeholder
            # for the current group
            if not self._runtest:
                self._tverbose()
            self.test_msgs.append([])
        # Match the given message to a sub-group or add it if no match
        grpid = self._subgroup_id(msg, tid)
        if subtest is not None:
            # A subtest is given so added to the proper sub-group
            subgroup = self.test_msgs[-1][grpid]
            subgroup[2].append([tid, subtest])
            if subgroup[0] == PASS and tid == FAIL:
                # Subtest failed so fail the subgroup
                subgroup[0] = FAIL
        if self.tverbose == 2 or (self.tverbose == 1 and subtest is None):
            # Display the test message if tverbose flag is set to verbose(2)
            # or if there is no subtest when tverbose is set to normal(1)
            self._msg_count[tid] += 1
            if subtest is not None:
                msg += subtest
            if failmsg is not None and tid == FAIL:
                msg += failmsg
            msg = msg.replace("\n", "\n          ")
            self._print_msg(msg, tid)

        if tid == HEAD:
            if self._runtest:
                self.dprint('INFO', "Running test '%s'" % self.testname)
            self._runtest = False
            if self.createtraces:
                self.trace_start()

    def _test_time(self):
        """Add an INFO message having the time difference between the current
           time and the time of the last call to this method.
        """
        self.test_time.append(time.time())
        if len(self.test_time) > 1:
            ttime = self.test_time[-1] - self.test_time[-2]
            self._test_msg(INFO, "TIME: %s" % self._print_time(ttime))

    def exit(self):
        """Terminate script with an exit value of 0 when all tests passed
           and a value of 1 when there is at least one test failure.
        """
        if self._msg_count[FAIL] > 0:
            sys.exit(1)
        else:
            sys.exit(0)

    def config(self, msg):
        """Display config message and terminate test with an exit value of 2."""
        msg = "CONFIG: " + msg
        msg = msg.replace("\n", "\n        ")
        self.write_log(msg)
        print msg
        sys.exit(2)

    def test_info(self, msg):
        """Display info message."""
        self._test_msg(INFO, msg)

    def test_group(self, msg):
        """Display heading message and start a test group.

           If tverbose=group or level 0:
               Group message is displayed as a PASS/FAIL message including the
               number of tests that passed and failed within this test group.
           If tverbose=normal|verbose or level 1|2:
               Group message is displayed as a heading messages for the tests
               belonging to this test group.
        """
        self._test_msg(HEAD, msg)

    def warning(self, msg):
        """Display warning message."""
        if self.warnings:
            self._test_msg(WARN, msg)

    def test(self, expr, msg, subtest=None, failmsg=None, terminate=False):
        """Test expr and display message as PASS/FAIL, terminate execution
           if terminate option is True.

           expr:
               If expr is true, display as a PASS message,
               otherwise as a FAIL message
           msg:
               Message to display
           subtest:
               If given, append this string to the displayed message and
               mark this test as a member of the sub-group given by msg
           failmsg:
               If given, append this string to the displayed message when
               expr is false [default: None]
           terminate:
               Terminate execution if true and expr is false [default: False]

           If tverbose=normal or level 1:
               Sub-group message is displayed as a PASS/FAIL message including
               the number of tests that passed and failed within the sub-group
           If tverbose=verbose or level 2:
               All tests messages are displayed
        """
        tid = PASS if expr else FAIL
        if len(self._bugmsgs):
            for tmsg in self._bugmsgs:
                if re.search(tmsg, msg):
                    if self.ignore:
                        # Do not count as a failure if bugmsgs and ignore are set
                        # and it is a failure
                        tid = IGNR if tid == FAIL else tid
                    else:
                        # Do not count as a failure if bugmsgs is set and it is a failure
                        tid = BUG  if tid == FAIL else tid
                        # Count as a failure if bugmsgs is set and the test actually passed
                        tid = FAIL if tid == PASS else tid
                        if tid == FAIL:
                            failmsg = " -- test actually PASSed but failing because --bugmsgs is used"
                    break
        self._test_msg(tid, msg, subtest=subtest, failmsg=failmsg)
        if tid == FAIL and terminate:
            self.exit()

    def testid_count(self, tid):
        """Return the number of instances the testid has occurred."""
        return self._msg_count[tid]

    def abspath(self, filename, dir=None):
        """Return the absolute path for the given file name."""
        path = self.abshash.get(filename)
        if path is None:
            bdir = "" if dir is None else "%s/" % dir
            path = "%s/%s%s" % (self.mtdir, bdir, filename)
        return path

    def get_name(self):
        """Get unique name for this instance."""
        if not self._name:
            t = time.localtime()
            self._name = "%s_%d_%d%02d%02d%02d%02d%02d" % (self.progname, os.getpid(), t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)
        return self._name

    def get_dirname(self, dir=None):
        """Return a unique directory name under the given directory."""
        self.dirname = "%s_d_%d" % (self.get_name(), self.diridx)
        self.diridx += 1
        self.absdir = self.abspath(self.dirname, dir=dir)
        self.abshash[self.dirname] = self.absdir
        self.dirs.append(self.dirname)
        self.remove_list.append(self.absdir)
        return self.dirname

    def get_filename(self, dir=None):
        """Return a unique file name under the given directory."""
        self.filename = "%s_f_%d" % (self.get_name(), self.fileidx)
        self.fileidx += 1
        self.absfile = self.abspath(self.filename, dir=dir)
        self.abshash[self.filename] = self.absfile
        self.files.append(self.filename)
        self.remove_list.append(self.absfile)
        return self.filename

    def data_pattern(self, offset, size, pattern=None):
        """Return data pattern.

           offset:
               Starting offset of pattern
           size:
               Size of data to return
           pattern:
               Data pattern to return, default is of the form:
               hex_offset(0x%08X) abcdefghijklmnopqrst\\n
        """
        data = ''
        if pattern is None:
            pattern = 'abcdefghijklmnopqrst'
            line_len = 32
            default = True
        else:
            line_len = len(pattern)
            default = False

        s_offset = offset % line_len
        offset = offset - s_offset
        N = int(0.9999 + (size + s_offset) / float(line_len))

        for i in range(0,N):
            if default:
                str_offset = "0x%08X " % offset
                plen = 31 - len(str_offset)
                data += str_offset + pattern[:plen] + '\n'
                offset += line_len
            else:
                data += pattern
        return data[s_offset:size+s_offset]

    def delay_io(self, delay=None):
        """Delay I/O by value given or the value given in --iodelay option."""
        if delay is None:
            delay = self.iodelay
        if not self.nomount and len(self.basename) == 0:
            # Slow down traffic for tcpdump to capture all packets
            time.sleep(delay)

    def create_dir(self, dir=None, mode=0755):
        """Create a directory under the given directory with the given mode."""
        self.get_dirname(dir=dir)
        self.dprint('DBG3', "Creating directory [%s]" % self.absdir)
        os.mkdir(self.absdir, mode)
        return self.dirname

    def create_file(self, offset=0, size=None, dir=None, mode=None):
        """Create a file starting to write at given offset with total size
           of written data given by the size option.

           offset:
               File offset where data will be written to [default: 0]
           size:
               Total number of bytes to write [default: --filesize option]
           dir:
               Create file under this directory
           mode:
               File permissions [default: use default OS permissions]

           Returns the file name created, the file name is also stored
           in the object attribute filename -- attribute absfile is also
           available as the absolute path of the file just created.

           File created is removed at object destruction.
        """
        self.get_filename(dir=dir)
        if size is None:
            size = self.filesize

        self.dprint('DBG3', "Creating file [%s] %d@%d" % (self.absfile, size, offset))
        fd = os.open(self.absfile, os.O_WRONLY|os.O_CREAT|os.O_SYNC)
        try:
            if offset:
                os.lseek(fd, offset, 0)
            os.write(fd, self.data_pattern(offset, size))
        finally:
            os.close(fd)
        if mode != None:
            os.chmod(self.absfile, mode)
        return self.filename

    def _reset_files(self):
        """Reset state used in *_files() methods."""
        self.roffset = 0
        self.woffset = 0
        self.rfds = []
        self.wfds = []

    def open_files(self, mode, create=True):
        """Open files according to given mode, the file descriptors are saved
           internally to be used with write_files(), read_files() and
           close_files(). The number of files to open is controlled by
           the command line option '--nfiles'.

           The mode could be either 'r' or 'w' for opening files for reading
           or writing respectively. The open flags for mode 'r' is O_RDONLY
           while for mode 'w' is O_WRONLY|O_CREAT|O_SYNC. The O_SYNC is used
           to avoid the client buffering the written data.
        """
        for i in range(self.nfiles):
            if mode[0] == 'r':
                file = self.abspath(self.files[i])
                self.dprint('DBG3', "Open file for reading: %s" % file)
                fd = os.open(file, os.O_RDONLY)
                self.rfds.append(fd)
                self.lock_type = fcntl.F_RDLCK
            elif mode[0] == 'w':
                if create:
                    self.get_filename()
                    file = self.absfile
                else:
                    file = self.abspath(self.files[i])
                self.dprint('DBG3', "Open file for writing: %s" % file)
                # Open file with O_SYNC to avoid client buffering the write requests
                fd = os.open(file, os.O_WRONLY|os.O_CREAT|os.O_SYNC)
                self.wfds.append(fd)
                self.lock_type = fcntl.F_WRLCK

    def close_files(self):
        """Close all files opened by open_files()."""
        for fd in self.wfds + self.rfds:
            self.dprint('DBG3', "Closing file")
            os.close(fd)
        self._reset_files()

    def write_files(self):
        """Write a block of data (size given by --wsize) to all files opened
           by open_files() for writing.
        """
        for fd in self.wfds:
            self.dprint('DBG4', "Write file %d@%d" % (self.wsize, self.woffset))
            os.write(fd, self.data_pattern(self.woffset, self.wsize))
        self.woffset += self.offset_delta

    def read_files(self):
        """Read a block of data (size given by --rsize) from all files opened
           by open_files() for reading.
        """
        for fd in self.rfds:
            self.dprint('DBG4', "Read file %d@%d" % (self.rsize, self.roffset))
            os.lseek(fd, self.roffset, 0)
            os.read(fd, self.rsize)
        self.roffset += self.offset_delta

    def lock_files(self, lock_type=None, offset=0, length=0):
        """Lock all files opened by open_files()."""
        if lock_type is None:
            lock_type = self.lock_type
        ret = []
        mode_str = 'WRITE' if lock_type == fcntl.F_WRLCK else 'READ'
        lockdata = struct.pack('hhllhh', lock_type, 0, long(offset), long(length), 0, 0)
        for fd in self.rfds + self.wfds:
            try:
                self.dprint('DBG3', "Lock file F_SETLKW (%s)" % mode_str)
                rv = fcntl.fcntl(fd, fcntl.F_SETLKW, lockdata)
                ret.append(rv)
            except Exception, e:
                self.warning("Unable to get lock on file: %r" % e)
        return ret
