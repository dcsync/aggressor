#!/usr/bin/env python3

import sys
import utils
sys.path.insert(0, utils.basedir('pycobalt'))
import time

import pycobalt.engine as engine
import pycobalt.aggressor as aggressor
import pycobalt.helpers as helpers
import pycobalt.events as events
import pycobalt.gui as gui

import sleep
import cleanup

def sleep_callback(bids):
    def finish(text):
        parts = text.split()

        # sleep
        pretty_time = parts[0]

        # jitter
        if len(parts) > 1:
            jitter = int(parts[1])
        else:
            jitter = 30

        for bid in bids:
            aggressor.btask(bid, 'sl {} {}'.format(pretty_time, jitter))
            sleep.sleep(bid, pretty_time, jitter)

    aggressor.prompt_text('sleep [jitter=30]', '', finish)

def shell_callback(bids):
    def finish(text):
        for bid in bids:
            aggressor.bshell(bid, text)

    aggressor.prompt_text('Shell command', '', finish)

def powerpick_callback(bids):
    def finish(text):
        for bid in bids:
            aggressor.bpowerpick(bid, text)

    aggressor.prompt_text('Powerpick command', '', finish)

def alias_callback(bids):
    def finish(text):
        if ' ' in text:
            parts = text.split(' ')
            alias = parts[0]
            args = ' '.join(parts[1:])
        else:
            alias = text
            args = ''

        for bid in bids:
            aggressor.binput(bid, text)
            aggressor.fireAlias(bid, alias, args)
            # I think fireAlias is broken somewhere. possibly on cobaltstrike's side?
            time.sleep(0.5)

    aggressor.prompt_text('Alias command', '', finish)

def eval_callback(bids):
    def finish(text):
        for bid in bids:
            code = '$bid = {}; $b = $bid; '.format(bid) + text
            aggressor.binput(bid, 'eval ' + text)
            engine.eval(code)

    aggressor.prompt_text('Eval code ($bid and $b will be set to the bid)', '', finish)

def clear_callback(bids):
    for bid in bids:
        aggressor.bclear(bid)

def caffeinate_callback(bids):
    for bid in bids:
        aggressor.bsleep(bid, 0, 0)

def suicide_callback(bids, b=None, c=None):
    engine.message('bc')
    engine.message(b)
    engine.message(c)
    for bid in bids:
        cleanup.suicide(bid)

menu = gui.popup('beacon_bottom', children=[
    gui.menu('&Batch', children=[
        gui.item('&Sleep', sleep_callback),
        gui.separator(),
        gui.item('&Shell', shell_callback),
        gui.item('&Powerpick', powerpick_callback),
        gui.item('&Alias', alias_callback),
        gui.item('&Eval', eval_callback),
        gui.separator(),
        gui.item('&Clear', clear_callback),
        gui.item('&Caffeinate', caffeinate_callback),
        gui.item('&Suicide', suicide_callback),
    ])
])

gui.register(menu)
