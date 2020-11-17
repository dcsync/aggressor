#!/usr/bin/env python3

import sys
import utils
sys.path.insert(0, utils.basedir('pycobalt'))

import pycobalt.engine as engine
import pycobalt.events as events
import pycobalt.commands as commands
import pycobalt.aliases as aliases
import pycobalt.aggressor as aggressor
import pycobalt.callbacks as callbacks
import pycobalt.helpers as helpers
import pycobalt.sharpgen as sharpgen
import pycobalt.console as console
from pycobalt.helpers import powershell_quote

@commands.command('python-debug')
def _(mode):
    if mode == 'on':
        engine.enable_debug()
    elif mode == 'off':
        engine.disable_debug()
    else:
        engine.error('python-debug on|off')
