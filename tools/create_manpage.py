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
import os
import re
import sys
import glob
import time
import subprocess
import nfstest_config as c

# Module constants
__author__    = 'Jorge Mora (%s)' % c.NFSTEST_AUTHOR_EMAIL
__version__   = '1.0.1'
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"

def _get_modules(script):
    fd = open(script, 'r')
    modules = {}
    for line in fd.readlines():
        line = line.lstrip().rstrip()
        m = re.search(r'^(from|import)\s+(.*)', line)
        if m:
            mods = m.group(2)
            mods = mods.split(' as ')[0]
            modlist = mods.split(' import ')
            mod_entries = []
            for mods in modlist:
                mods = mods.split(',')
                mod_entries.append([])
                for item in mods:
                    mod_entries[-1].append(item.strip())
            if mod_entries:
                for mods in mod_entries[0]:
                    modules[mods] = 1
                if len(mod_entries) > 1:
                    for mods in mod_entries[0]:
                        for item in mod_entries[1]:
                            modules['.'.join([mods, item])] = 1
    fd.close()
    return modules.keys()

def _get_see_also(src, modules, local_mods):
    parent_objs = {}
    for item in modules:
        if item not in local_mods and item[0] != '_':
            osrc = item.replace('.', '/')
            osrcpy = osrc + '.py'
            if src in (osrc, osrcpy):
                continue
            mangz = c.NFSTEST_MAN_MAP.get(osrc) or c.NFSTEST_MAN_MAP.get(osrcpy)
            obj = "\\fB%s\\fR" % os.path.split(item)[1]
            if mangz:
                m = re.search(r'([^\.]+)\.gz$', mangz)
                if m:
                    obj += "(%s)" % m.group(1)
                    parent_objs[obj] = 1
    objs = parent_objs.keys()
    objs.sort()
    return ', '.join(objs)

def _check_script(script):
    fd = open(script, 'r')
    line = fd.readline()
    fd.close()
    if re.search('^#!.*python', line):
        return True
    return False

def _lstrip(lines, br=False):
    ret = []
    minsps = 99999
    for line in lines:
        # Ignore blank lines
        if len(line) == 0:
            continue
        nsp = len(line) - len(line.lstrip())
        minsps = min(minsps, nsp)
    for line in lines:
        line = line[minsps:]
        if len(line.lstrip()) > 0:
            if br and line.lstrip()[0] in ('#', '$', '%'):
                ret.append('.br')
            if line[0] in ("'", '"'):
                line = '\\t' + line
        ret.append(line)
    return ret

def _process_func(lines):
    ret = []
    in_arg = False
    need_re = False
    count = 0
    for line in _lstrip(lines):
        if re.search(r'^[a-z]\w*:', line):
            if not in_arg:
                # Start indented region
                ret.append('.RS')
                need_re = True
            ret.append('.TP\n.B')
            in_arg = True
        elif len(line) == 0:
            if in_arg:
                # End of indented region
                ret.append('.RE\n.RS')
            in_arg = False
        elif in_arg:
            line = line.lstrip()
        if len(line) and line[0] == '#':
            count += 1
        ret.append(line)
    if count >= len(ret) - 1:
        ret_new = []
        for line in ret:
            ret_new.append(line.lstrip('#'))
        ret = ret_new
    if need_re:
        ret.append('.RE')
    return ret

def create_manpage(src, dst):
    usage = ''
    summary = ''
    desc_lines = []
    description = ''
    author = '%s (%s)' % (c.NFSTEST_AUTHOR, c.NFSTEST_AUTHOR_EMAIL)
    notes = []
    examples = []
    bugs = ''
    see_also = ''
    version = ''
    classes = []
    func_list = []
    test = {}
    tests = []
    option = {}
    options = []
    section = ''
    dlineno = 0
    requirements = []
    installation = []
    progname = ''

    is_script = _check_script(src)

    if not os.path.isdir(dst):
        manpage = dst
    elif is_script:
        manpage = os.path.join(dst, os.path.splitext(os.path.split(src)[1])[0] + '.1')
    else:
        #XXX use another section for modules
        manpage = os.path.splitext(src)[0].replace('/', '.') + '.1'
        manpage = manpage.lstrip('.')
    manpagegz = manpage + '.gz'

    fst = os.stat(src)
    if os.path.exists(manpagegz) and fst.st_mtime < os.stat(manpagegz).st_mtime:
        return

    print "Creating man page for %s" % src
    modules = _get_modules(src)

    if src == 'README':
        fd = open(src, 'r')
        lines = []
        for line in fd.readlines():
            lines.append(line.rstrip())
        fd.close()
        progname = 'NFStest'
    elif is_script:
        cmd = "%s --version" % src
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pstdout, pstderr = proc.communicate()
        proc.wait()
        version = pstdout.split()[1]

        cmd = "%s --help" % src
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pstdout, pstderr = proc.communicate()
        proc.wait()
        lines = re.sub('Total time:.*', '', pstdout).split('\n')
    else:
        absmodule = os.path.splitext(src)[0].replace('/', '.')
        cmd = "pydoc %s" % absmodule
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pstdout, pstderr = proc.communicate()
        proc.wait()
        lines = pstdout.split('\n')

    for line in lines:
        if is_script and len(usage) == 0:
            m = re.search(r'^Usage:\s+(.*)', line)
            usage = m.group(1)
            continue
        elif len(summary) == 0:
            if len(line) > 0:
                if re.search(r'^FILE', line):
                    summary = ' '
                    continue
                else:
                    summary = ' - ' + line
                section = 'description'
            continue
        elif len(line) > 0 and line[0] == '=':
            continue
        elif re.search(r'^Requirements and limitations', line):
            section = 'requirements'
            continue
        elif re.search(r'^Tests', line):
            section = 'tests'
            continue
        elif re.search(r'^Installation', line):
            section = 'installation'
            continue
        elif re.search(r'^Run the tests', line):
            section = 'examples'
            continue
        elif re.search(r'^Useful options', line):
            section = 'options'
            continue
        elif re.search(r'^Examples:', line):
            section = 'examples'
            continue
        elif re.search(r'^Notes:', line):
            section = 'notes'
            continue
        elif re.search(r'^Available tests:', line):
            section = 'tests'
            continue
        elif re.search(r'^Options:', line):
            section = 'options'
            continue
        elif re.search(r'^NAME', line):
            section = 'name'
            continue
        elif re.search(r'^DESCRIPTION', line):
            section = 'desc'
            continue
        elif re.search(r'^CLASSES', line):
            section = 'class'
            continue
        elif re.search(r'^FUNCTIONS', line):
            section = 'funcs'
            continue
        elif re.search(r'^DATA', line):
            section = 'data'
            continue
        elif re.search(r'^VERSION', line):
            section = 'version'
            continue
        elif re.search(r'^AUTHOR', line):
            section = 'author'
            continue

        if section == 'name':
            section = ''
            m = re.search(r'^\s*(\S+)(.*)', line)
            progname = m.group(1)
            summary = m.group(2)
        elif section == 'desc':
            desc_lines.append(line)
        elif section == 'description':
            if progname == 'NFStest':
                if re.search(r'^\s*=+', line):
                    if dlineno == 0:
                        dlineno = len(desc_lines) - 1
                    desc_lines[-1] = re.sub(r'^(\s*)', r'\1.SS ', desc_lines[-1])
                else:
                    desc_lines.append(line)
            else:
                description += line + '\n'
        elif section == 'requirements':
            requirements.append(line)
        elif section == 'examples':
            examples.append(line)
        elif section == 'notes':
            notes.append(line)
        elif section == 'tests':
            if progname == 'NFStest':
                if re.search(r'^\s*=+', line):
                    continue
                testname = re.search(r'\s*(\w+)\s+-', line)
            else:
                testname = re.search(r'\s*(.*):$', line)
            if testname:
                if test:
                    tests.append(test)
                    test = {}
                test['name'] = testname.group(1)
                test['desc'] = []
            else:
                test['desc'].append(line)
        elif section == 'installation':
            installation.append(line)
        elif section == 'options':
            if progname == 'NFStest':
                optsname = re.search(r'^(--.+)', line)
            else:
                optsname = re.search(r'^\s*(.*--(\S+))\s*(.*)', line)
            if optsname:
                if option:
                    options.append(option)
                    option = {}
                option['name'] = optsname.group(1)
                if len(optsname.groups()) >= 3 and len(optsname.group(3)) > 0:
                    option['desc'] = [optsname.group(3)]
                else:
                    option['desc'] = []
            else:
                if progname == 'NFStest':
                    option['desc'].append(line)
                else:
                    option['desc'].append(line.lstrip())
        elif section == 'class':
            line = line.lstrip().lstrip('|')
            classes.append(line)
        elif section == 'funcs':
            func_list.append(line)
        elif section == 'version':
            section = ''
            version = line.lstrip()
        elif section == 'author':
            section = ''
            author = line.lstrip()

    if test and section != 'tests':
        tests.append(test)
        test = {}

    class_list = []
    if classes:
        # Process all classes
        for line in classes:
            m = re.search(r'^class\s+(\w+)(.*)', line)
            if m:
                class_list.append({'name': m.group(1), 'proto': m.group(2), 'body': [], 'res': []})
            elif class_list:
                class_list[-1]['body'].append(line)
        for cls in class_list:
            body = []
            method_desc = []
            in_methods = False
            in_inherit = False
            in_resolution = False
            for line in _lstrip(cls['body']):
                if re.search(r'^Data descriptors defined here:', line):
                    break
                if len(line) > 1 and line == '-' * len(line):
                    continue
                elif re.search(r'^Method resolution order:', line):
                    in_resolution = True
                    in_methods = False
                elif re.search(r'^(Static )?[mM]ethods inherited', line):
                    in_inherit = True
                    in_methods = False
                elif re.search(r'^(Static )?[mM]ethods defined here:', line):
                    body += _process_func(method_desc)
                    method_desc = []
                    body.append('.P\n.B %s\n.br\n%s' % (line, '-' * len(line)))
                    in_methods = True
                elif in_methods and re.search(r'^\w+(\s+=\s+\w+)?\(', line):
                    body += _process_func(method_desc)
                    method_desc = []
                    body.append('.TP')
                    body.append('.B %s' % line)
                elif in_methods:
                    method_desc.append(line)
                elif in_resolution:
                    if len(line) == 0:
                        in_resolution = False
                    else:
                        cls['res'].append(line.lstrip())
                elif not in_inherit and not in_resolution:
                    body.append(line)
            body += _process_func(method_desc)
            cls['body'] = body

    all_modules = modules
    local_mods = []
    for cls in class_list:
        if cls['body']:
            mods = []
            for item in cls['res']:
                mods.append(item)
                obj = '.'.join(item.split('.')[:-1])
                if len(obj):
                    mods.append(obj)
            all_modules += mods
            local_mods.append(cls['name'])
    all_modules += c.NFSTEST_SCRIPTS if is_script or progname == 'NFStest' else []
    see_also += _get_see_also(src, all_modules, local_mods)

    # Get a list of functions included from imported modules
    mod_funcs = []
    for mod in modules:
        data = mod.split(".")
        if len(data) > 1:
            mod_funcs.append(data[-1])

    func_desc = []
    functions = []
    is_local_function = False
    for line in _lstrip(func_list):
        regex = re.search(r'(\w+)\((.*)\)', line)
        if regex:
            data = regex.groups()
            is_local_function = False
            functions += _process_func(func_desc)
            func_desc = []
            if data[1] != "..." or data[0] not in mod_funcs:
                # Only include functions defined locally,
                # do not include any function from imported modules
                functions.append('.TP')
                functions.append('.B %s' % line)
                is_local_function = True
        elif is_local_function:
            func_desc.append(line)
    functions += _process_func(func_desc)

    if option:
        options.append(option)

    if progname == 'NFStest':
        description += '\n'.join(_lstrip(desc_lines[:dlineno]))
        description += '\n'.join(_lstrip(desc_lines[dlineno:]))
    elif desc_lines:
        description += '\n'.join(_lstrip(desc_lines))

    if is_script:
        progname = os.path.splitext(usage.split()[0])[0]

    pname = progname.split('.')[-1]
    datestr = time.strftime("%e %B %Y")

    # Open man page to create
    fd = open(manpage, 'w')

    thisprog = os.path.split(sys.argv[0])[1]
    print >>fd, '.\\" DO NOT MODIFY THIS FILE!  It was generated by %s %s.' % (thisprog, __version__)
    nversion = "%s %s" % (c.NFSTEST_PACKAGE, c.NFSTEST_VERSION)
    print >>fd, '.TH %s 1 "%s" "%s" "%s %s"' % (pname.upper(), datestr, nversion, pname, version)
    print >>fd, '.SH NAME'
    print >>fd, '%s%s' % (progname, summary)
    if len(usage):
        print >>fd, '.SH SYNOPSIS'
        print >>fd, usage
    if len(description) and description != '\n':
        print >>fd, '.SH DESCRIPTION'
        print >>fd, description
    if requirements:
        print >>fd, '.SH REQUIREMENTS AND LIMITATIONS'
        print >>fd, '\n'.join(_lstrip(requirements))
    if class_list:
        print >>fd, '.SH CLASSES'
        for cls in class_list:
            if cls['body']:
                print >>fd, ".SS class %s%s" % (cls['name'], cls['proto'])
                for line in cls['body']:
                    print >>fd, line
    if functions:
        print >>fd, '.SH FUNCTIONS'
        for line in functions:
            print >>fd, line
    if options and progname != 'NFStest':
        print >>fd, '.SH OPTIONS'
        for option in options:
            print >>fd, '.TP'
            print >>fd, '.B %s' % option['name']
            print >>fd, '\n'.join(_lstrip(option['desc']))
    if tests:
        print >>fd, '.SH TESTS'
        for test in tests:
            #print >>fd, '.TP'
            print >>fd, '.SS %s' % test['name']
            print >>fd, '\n'.join(_lstrip(test['desc']))

    if installation:
        print >>fd, '.SH INSTALLATION'
        print >>fd, '\n'.join(_lstrip(installation))

    if examples:
        print >>fd, '.SH EXAMPLES'
        print >>fd, '\n'.join(_lstrip(examples, br=True))

    if options and progname == 'NFStest':
        print >>fd, '.SH USEFUL OPTIONS'
        for option in options:
            print >>fd, '.TP'
            print >>fd, '.B %s' % option['name']
            print >>fd, '\n'.join(_lstrip(option['desc']))
    if notes:
        print >>fd, '.SH NOTES'
        print >>fd, '\n'.join(_lstrip(notes))

    if len(see_also) > 0:
        print >>fd, '.SH SEE ALSO'
        print >>fd, see_also

    print >>fd, '.SH BUGS'
    if len(bugs) > 0:
        print >>fd, bugs
    else:
        print >>fd, 'No known bugs.'

    print >>fd, '.SH AUTHOR'
    print >>fd, author
    fd.close()
    cmd = "gzip -f --stdout %s > %s.gz" % (manpage, manpage)
    os.system(cmd)

def run():
    if not os.path.exists(c.NFSTEST_MANDIR):
        os.mkdir(c.NFSTEST_MANDIR)
    for (script, manpagegz) in c.NFSTEST_MAN_MAP.items():
        manpage = os.path.splitext(manpagegz)[0]
        create_manpage(script, manpage)

######################################################################
# Entry
if __name__ == '__main__':
    if len(sys.argv) > 1:
        dir = sys.argv[2] if len(sys.argv) == 3 else '.'
        create_manpage(sys.argv[1], dir)
    else:
        run()
