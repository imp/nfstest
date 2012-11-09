#!/usr/bin/env python
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
#
# To create man pages:
# $ python setup.py build
#
# To install, run as root:
# $ python setup.py install
#
# To create an rpm (need to create the man pages first):
# $ python setup.py build
# $ python setup.py bdist_rpm --release p2.6
#
import os
import nfstest_config as c
from tools import create_manpage
from distutils.core import setup
from distutils.command.build import build

class Build(build):
    def run(self):
        create_manpage.run()
        build.run(self)

setup(
    name             = c.NFSTEST_PACKAGE,
    version          = c.NFSTEST_VERSION,
    description      = c.NFSTEST_SUMMARY,
    long_description = c.NFSTEST_DESCRIPTION,
    author           = c.NFSTEST_AUTHOR,
    author_email     = c.NFSTEST_AUTHOR_EMAIL,
    maintainer       = c.NFSTEST_MAINTAINER,
    maintainer_email = c.NFSTEST_MAINTAINER_EMAIL,
    license          = c.NFSTEST_LICENSE,
    url              = c.NFSTEST_URL,
    download_url     = c.NFSTEST_DL_URL,
    py_modules       = c.NFSTEST_MODULES,
    packages         = c.NFSTEST_PACKAGES,
    scripts          = c.NFSTEST_SCRIPTS,
    cmdclass = {'build': Build},
    data_files = [
        # Man pages for scripts
        (os.path.join(c.NFSTEST_USRMAN, 'man1'), c.NFSTEST_MAN1),
    ],
)
