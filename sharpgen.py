#!/usr/bin/env python3

import sys
import utils
sys.path.insert(0, utils.basedir('pycobalt'))

import pycobalt.engine as engine
import pycobalt.events as events
import pycobalt.aliases as aliases
import pycobalt.helpers as helpers
import pycobalt.commands as commands
import pycobalt.aggressor as aggressor
import pycobalt.callbacks as callbacks
import pycobalt.sharpgen as sharpgen

import config

cache = False

@aliases.alias('sharpgen-execute', 'Execute C# code using SharpGen', quote_replacement='^')
def _(bid, code, *args):
    aggressor.btask(bid, 'Tasked beacon to execute C# code: {}'.format(code))
    try:
        from_cache = sharpgen.execute(bid, code, args, cache=cache)

        if from_cache:
            aggressor.blog2(bid, 'Build was retrieved from the cache')
    except RuntimeError as e:
        aggressor.berror(bid, 'SharpGen failed. See Script Console for more details.')

@aliases.alias('sharpgen-execute-file', 'Execute C# code from a file using SharpGen', quote_replacement='^')
def _(bid, source, *args):
    aggressor.btask(bid, 'Tasked beacon to execute C# code from: {}'.format(source))
    try:
        from_cache = sharpgen.execute_file(bid, source, args, cache=cache)

        if from_cache:
            aggressor.blog2(bid, 'Build was retrieved from the cache')
    except RuntimeError as e:
        aggressor.berror(bid, 'SharpGen failed. See Script Console for more details.')

# Compile C# code using SharpGen
@commands.command('sharpgen-compile', quote_replacement='^')
def _(code, out=None, *sharpgen_flags):
    engine.message('Compiling C# code: {}'.format(code))
    try:
        out, from_cache = sharpgen.compile(code, out=out, additional_options=sharpgen_flags, cache=cache)

        if from_cache:
            engine.message('Build was found in the cache! Output is in: {}'.format(out))
        else:
            engine.message('Build was successful! Output is in: {}'.format(out))
    except RuntimeError as e:
        engine.error('SharpGen failed. See above for more details.')

# Compile C# code from file using SharpGen
@commands.command('sharpgen-compile-file', quote_replacement='^')
def _(source, out=None, *sharpgen_flags):
    engine.message('Compiling C# code from: {}'.format(source))
    try:
        out, from_cache = sharpgen.compile_file(source, out=out, additional_options=sharpgen_flags, cache=cache)

        if from_cache:
            engine.message('Build was found in the cache! Output is in: {}'.format(out))
        else:
            engine.message('Build was successful! Output is in: {}'.format(out))
    except RuntimeError as e:
        engine.error('SharpGen failed. See above for more details.')

# Clear the SharpGen build cache
@commands.command('sharpgen-cache-clear')
def _():
    sharpgen.clear_cache()
    engine.message('Cleared the SharpGen build cache')

# Toggle cache overwrite mode
@commands.command('sharpgen-cache-overwrite')
def _(mode):
    if mode == 'on':
        sharpgen.enable_cache_overwrite()
        engine.message('Enabled SharpGen cache overwrite')
    elif mode == 'off':
        sharpgen.disable_cache_overwrite()
        engine.message('Disabled SharpGen cache overwrite')
    else:
        engine.error('Usage: sharpgen-cache-overwrite on|off')

# Toggle SharpGen ConfuserEx
@commands.command('sharpgen-confuser')
def _(mode):
    if mode == 'on':
        sharpgen.set_confuser_protections(config.protections_net35)
        engine.message('Enabled SharpGen ConfuserEx protections')
    elif mode == 'off':
        sharpgen.set_confuser_protections(None)
        engine.message('Disabled SharpGen ConfuserEx protections')
    else:
        engine.error('Usage: sharpgen-confuser on|off')
