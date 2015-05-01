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
Remote procedure module

Provides a set of tools for executing a wide range commands, statements,
expressions or functions on a remote host by running a server process
on the remote host serving requests without disconnecting. This allows
for a sequence of operations to be done remotely and not losing state.
A file could be opened remotely, do some other things and then write
to the same opened file without opening the file again.

In order to use this module the user id must be able to 'ssh' to the
remote host without the need for a password.
"""
import os
import re
import inspect
import nfstest_config as c
from baseobj import BaseObj
from subprocess import Popen, PIPE
from multiprocessing.connection import Client

# Module constants
__author__    = 'Jorge Mora (%s)' % c.NFSTEST_AUTHOR_EMAIL
__version__   = '1.0.1'
__copyright__ = "Copyright (C) 2013 NetApp, Inc."
__license__   = "GPL v2"

# Constants
PORT = 9900

# This is a the server which is sent using the ssh command
# It is minimal just to get a connection and execute the
# real remote procedure server to service requests
def bare_server(port, logfile):
    """Bare-bones remote server"""
    from multiprocessing.connection import Listener

    fd = open(logfile, "w", 0)
    address = ("", port)
    listener = Listener(address)
    conn = listener.accept()
    fd.write("Connection accepted\n")
    # Wait for main server and execute it
    msg = conn.recv()
    try:
        exec(msg)
    except Exception as e:
        fd.write("ERROR: %r\n" % e)
    fd.close()
    listener.close()

def proc_requests(fd, conn):
    """Main remote procedure server

       fd:
           File descriptor for logfile
       conn:
           Connection object
    """
    import types
    fd.write("Running proc_requests\n")
    while True:
        msg = conn.recv()
        fd.write("Received %r\n" % msg)
        if type(msg) is dict:
            try:
                # Get command
                cmd  = msg.get('cmd')
                # Get function/statement/expression and positional arguments
                kwts = msg.get('kwts', ())
                fstr = kwts[0]
                kwts = kwts[1:]
                # Get named arguments
                kwds = msg.get('kwds', {})
            except Exception as e:
                fd.write("\nERROR: %r\n" % e)
                conn.send(e)
            if cmd == 'run':
                # Call function
                try:
                    # Find if function is defined
                    fd.write("Run '%s'" % fstr)
                    if type(fstr) in [types.FunctionType, types.BuiltinFunctionType, types.MethodType]:
                        # This is a function
                        func = fstr
                    else:
                        # Find symbol in globals then in locals
                        func = globals().get(fstr)
                        if func is None:
                            func = locals().get(fstr)
                    if func is None:
                        raise Exception("function not found")
                    # Run function with all its arguments
                    conn.send(func(*kwts, **kwds))
                    fd.write("...done\n")
                except Exception as e:
                    fd.write("\nERROR: %r\n" % e)
                    conn.send(e)
            elif cmd == 'eval':
                # Evaluate expression
                try:
                    fd.write("Evaluate '%s'" % fstr)
                    out = eval(fstr)
                    fd.write("...done\n")
                    conn.send(out)
                except Exception as e:
                    fd.write("\nERROR: %r\n" % e)
                    conn.send(e)
            elif cmd == 'exec':
                # Execute statement
                try:
                    fd.write("Execute '%s'" % fstr)
                    exec(fstr)
                    fd.write("...done\n")
                    conn.send(None)
                except Exception as e:
                    fd.write("\nERROR: %r\n" % e)
                    conn.send(e)
            else:
                emsg = "Unknown procedure"
                fd.write("ERROR: %s\n" % emsg)
                conn.send(Exception(emsg))
        if msg == 'close':
            # Request to close the connection,
            # exit the loop and terminate the server
            conn.close()
            break

class Rexec(BaseObj):
    """Rexec object

       Rexec() -> New remote procedure object

       Arguments:
           servername:
               Name or IP address of remote server
           logfile:
               Name of logfile to create on remote server

       Usage:
           from nfstest.rexec import Rexec

           # Function to be defined at remote host
           def add_one(n):
               return n + 1

           # Function to be defined at remote host
           def get_time(delay=0):
               time.sleep(delay)
               return time.time()

           # Create remote procedure object
           x = Rexec("192.168.0.85")

           # Define function at remote host
           x.rcode(add_one)

           # Evaluate the expression calling add_one()
           out = x.reval("add_one(67)")

           # Run the function with the given argument
           out = x.run("add_one", 7)

           # Run built-in functions
           import time
           out = x.run(time.time)

           # Import libraries and symbols
           x.rimport("time", ["sleep"])
           x.run("sleep", 2)

           # Define function at remote host -- since function uses the
           # time module, this module must be first imported
           x.rimport("time")
           x.rcode(get_time)

           # Evaluate the expression calling get_time()
           out = x.reval("get_time()")

           # Run the function with the given argument
           out = x.run("get_time", 10)

           # Open file on remote host
           fd = x.run(os.open, "/tmp/testfile", os.O_WRONLY|os.O_CREAT|os.O_TRUNC)
           count = x.run(os.write, fd, "hello there\n")
           x.run(os.close, fd)

           # Use of positional arguments
           out = x.run('get_time', 2)

           # Use of named arguments
           out = x.run('get_time', delay=2)

           # Use of NOWAIT option for long running functions so other things
           # can be done while waiting
           x.run('get_time', 2, NOWAIT=True)
           while True:
               # Poll every 0.1 secs to see if function has finished
               if x.poll(0.1):
                   # Get results
                   out = x.results()
                   break
    """
    def __init__(self, servername="", logfile=None):
        """Constructor

           Initialize object's private data.

           servername:
               Host name or IP address of host where remote server will run
           logfile:
               Pathname of log file to be created on remote host
               [Default: "/dev/null"]
        """
        global PORT
        self.pid     = None
        self.conn    = None
        self.process = None
        if logfile is None:
            # Default log file
            logfile = "/dev/null"
        if servername in ["", "localhost", "127.0.0.1"]:
            # Start bare-bones server locally
            self.remote = False
            self.pid = os.fork()
            if self.pid == 0:
                # This is the child process
                bare_server(PORT, logfile)
                os._exit(0)
        else:
            # Start bare-bones server on remote host
            self.remote = True
            server_code = "".join(inspect.getsourcelines(bare_server)[0])
            server_code += 'bare_server(%d, "%s")' % (PORT, logfile)
            server_code = re.sub(r"'", r"\\'", server_code)
            cmdlist = ["ssh", "-t", servername, "python -c '%s'" % server_code]
            self.process = Popen(cmdlist, shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE)

        # Connect to remote server
        address = (servername, PORT)
        self.conn = Client(address)
        PORT += 1

        # Execute main server on remote host
        proc_code = "".join(inspect.getsourcelines(proc_requests)[0])
        proc_code += "proc_requests(fd, conn)"
        self.conn.send(proc_code)

    def __del__(self):
        """Destructor"""
        if self.conn:
            # Send command to exit main loop
            self.conn.send('close')
            self.conn.close()
        # Wait for remote server to finish
        if self.pid:
            os.waitpid(self.pid, 0)
        elif self.process:
            self.process.wait()

    def _send_cmd(self, cmd, *kwts, **kwds):
        """Internal method to send commands to remote server"""
        nowait = kwds.pop('NOWAIT', False)
        self.conn.send({'cmd': cmd, 'kwts': kwts, 'kwds': kwds})
        if nowait:
            # NOWAIT option is specified, so return immediately
            # Use poll() method to check if any data is available
            # Use results() method to get pending results from function
            return
        return self.results()

    def wait(self, objlist=None, timeout=0):
        """Return a list of Rexec objects where data is available to be read

           objlist:
               List of Rexec objects to poll, if not given use current object
           timeout:
               Maximum time in seconds to block, if timeout is None then
               an infinite timeout is used
        """
        ret = []
        if objlist is None:
            # Use current object as default
            objlist = [self]

        for obj in objlist:
            if obj.poll(timeout):
                ret.append(obj)
            # Just check all other objects if they are ready now
            timeout = 0
        return ret if len(ret) else None

    def poll(self, timeout=0):
        """Return whether there is any data available to be read

           timeout:
               Maximum time in seconds to block, if timeout is None then
               an infinite timeout is used
        """
        return self.conn.poll(timeout)

    def results(self):
        """Return pending results"""
        out = self.conn.recv()
        if isinstance(out, Exception):
            raise out
        return out

    def rexec(self, expr):
        """Execute statement on remote server"""
        return self._send_cmd('exec', expr)

    def reval(self, expr):
        """Evaluate expression on remote server"""
        return self._send_cmd('eval', expr)

    def run(self, *kwts, **kwds):
        """Run function on remote server

           The first positional argument is the function to be executed.
           All other positional arguments and any named arguments are treated
           as arguments to the function
        """
        return self._send_cmd('run', *kwts, **kwds)

    def rcode(self, code):
        """Define function on remote server"""
        codesrc = "".join(inspect.getsourcelines(code)[0])
        self.rexec(codesrc)

    def rimport(self, module, symbols=[]):
        """Import module on remote server

           module:
               Module to import in the remote server
           symbols:
               If given, import only these symbols from the module
        """
        # Import module
        if len(symbols) == 0:
            self.rexec("import %s" % module)
            symbols = [module]
        else:
            self.rexec("from %s import %s" % (module, ",".join(symbols)))
        # Make all symbols global
        for item in symbols:
            self.rexec("globals()['%s']=locals()['%s']" % (item, item))
