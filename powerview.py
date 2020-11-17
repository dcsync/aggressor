#!/usr/bin/env python3

import sys
import utils
sys.path.insert(0, utils.basedir('pycobalt'))

import textwrap

import pycobalt.engine as engine
import pycobalt.events as events
import pycobalt.commands as commands
import pycobalt.aliases as aliases
import pycobalt.aggressor as aggressor
import pycobalt.callbacks as callbacks
import pycobalt.helpers as helpers
import pycobalt.sharpgen as sharpgen
from pycobalt.helpers import powershell_quote

import powerview_generated
import external

functions = {**powerview_generated.functions}

# add aliases
for alias, function in powerview_generated.aliases.items():
    functions[alias] = 'PowerView alias for {}'.format(function)

# generate function aliases
for function, description in functions.items():
    def callback(bid, *args, function=function):
        external.run(bid, 'powerview', '{} {}'.format(function, ' '.join(args)))

    # get short help
    in_synopsis = False
    short_help = ''
    for line in description.splitlines():
        line = line.strip()
        if line == '.SYNOPSIS':
            in_synopsis = True
        elif short_help and not line:
            break
        elif in_synopsis:
            if short_help:
                short_help += ' '
            short_help += line

    if not short_help:
        short_help = 'PowerView function'

    aliases.register(function.lower(), callback, short_help, description)
