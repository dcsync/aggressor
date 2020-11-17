#!/usr/bin/env python3

import sys
import utils
sys.path.insert(0, utils.basedir('pycobalt'))

import pycobalt.engine as engine
import pycobalt.aggressor as aggressor
import pycobalt.gui as gui

def set_notes(bids, note):
    """
    Set notes for multiple beacons
    """

    for bid in bids:
        aggressor.bnote(bid, note)

notes = ('domain &controller!', 'database!', '&using', 'keylogger',
         'screenshotter', 'standby', 'sandbox', 'dead', 'new', 'do not use',
         'sysadmin', '!!!')
note_items = []

for note in notes:
    note_items.append(gui.item(note, callback=(lambda note: lambda bids: set_notes(bids, note.replace('&', '')))(note)))

note_items.append(gui.separator())
note_items.append(gui.item('&clear', callback=lambda bids: set_notes(bids, '')))

menu = gui.popup('beacon_bottom', children=[
    gui.menu('&Note', children=note_items)
])

gui.register(menu)
