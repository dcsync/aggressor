#!/usr/bin/env python3

import sys
import utils
sys.path.insert(0, utils.basedir('pycobalt'))

import collections

import pycobalt.engine as engine
import pycobalt.events as events
import pycobalt.commands as commands
import pycobalt.aliases as aliases
import pycobalt.aggressor as aggressor
import pycobalt.callbacks as callbacks

# for 'suicide' command
killing = set()
@events.event('beacon_output')
def _(bid, output, when):
    global killing

    if output == 'beacon exit.' and bid in killing:
        killing.remove(bid)
        aggressor.beacon_remove(bid)

# Kill and remove beacon.
def suicide(bid):
    global killing

    aggressor.bexit(bid)
    aggressor.bnote(bid, 'killing')
    killing.add(bid)

# Kill and remove beacon.
@aliases.alias('suicide', 'Kill and remove beacon')
def _(bid):
    suicide(bid)

# Remove a beacon.
@aliases.alias('remove', 'Remove this beacon')
def _(bid):
    aggressor.beacon_remove(bid)

# Prune dead beacons.
def prune_dead():
    for beacon in aggressor.beacons():
        if beacon['alive'] == 'false':
            bid = beacon['id']
            engine.message('removing beacon {} ({}@{})'.format(bid, beacon['user'], beacon['computer']))
            aggressor.beacon_remove(bid)

def older_than(last, hours):
    last = int(last)
    hours = int(hours)
    last_hours = last / 1000 / 60 / 60
    return last_hours > hours

def last_difference(newer, older):
    return float(int(older) - int(newer)) / 1000 / 60 / 60

# Prune beacons older than :hours:
def prune_old(hours):
    for beacon in aggressor.beacons():
        last = int(beacon['last'])

        if older_than(last, hours):
            bid = beacon['id']
            last_hours = last / 1000 / 60 / 60
            engine.message('removing beacon {} ({}@{}) ({} hours old)'.format(bid, beacon['user'], beacon['computer'], int(last_hours)))
            aggressor.beacon_remove(bid)

def cleanup(hours=80, dry=True):
    # collect notes
    notes = collections.defaultdict(set)
    for beacon in aggressor.beacons():
        # skip 'killing'
        if beacon['note'] == 'killing':
            continue

        ident = '{}@{}'.format(beacon['user'], beacon['computer'])
        notes[ident].add(beacon['note'])

    # remove dead
    if not dry:
        prune_dead()
    else:
        engine.message('not pruning dead beacons')

    # remove old
    #if not dry:
    #    prune_old(int(hours))
    #else:
    #    engine.message('not pruning old beacons')

    # collect beacons
    by_ident = collections.defaultdict(list)
    for beacon in aggressor.beacons():
        # skip dead beacons
        if beacon['alive'] == 'false':
            continue

        ident = '{}@{}'.format(beacon['user'], beacon['computer'])
        by_ident[ident].append(beacon)

    # sort beacons by newest
    for ident, beacons in by_ident.items():
        beacons = sorted(beacons, key=lambda b: int(b['last']))
        by_ident[ident] = beacons

    # de-duplicate
    for ident, beacons in by_ident.items():
        if len(beacons) > 1:
            # pick a beacon. to choose a selected beacon we:
            #   - find all beacons with last times within 2 hours of the newest beacon
            #   - pick the newest beacon of those with a note
            #   - or: pick the newest beacon
            #newest_beacon = beacons[0]
            #for beacon in beacons[1:]:
            #    if last_difference(newest_beacon['last'], beacon['last']) > 1.0:
            #        if beacon['note']:
            #            # newest beacon with a note
            #            picked_beacon = beacon
            #            break
            #else:
            #    # newest beacon
            #    picked_beacon = beacons[0]

            picked_beacon = list(filter(lambda b: b['note'] != 'killing', beacons))[0]
            beacons.remove(picked_beacon)

            # kill or remove the other beacons
            for beacon in beacons:
                if {'keep', 'test'} & set(beacon['note'].split()):
                    # special note. don't kill
                    engine.message('not touching beaacon with keep note {} {}'.format(ident, beacon['note']))
                elif last_difference(picked_beacon['last'], beacon['last']) > 2.0:
                    # probably dead. just remove
                    engine.message('removing older beacon {} {}'.format(ident, beacon['id']))
                    if not dry:
                        aggressor.beacon_remove(beacon['id'])
                else:
                    # kill and remove
                    engine.message('killing older beacon {} {}'.format(ident, beacon['id']))
                    if not dry:
                        suicide(beacon['id'])

            # pick shortest note
            picked_note = None
            for note in notes[ident]:
                if not picked_note or len(picked_note) > note:
                    picked_note = note

            if picked_note:
                engine.message('{} picked note: {}'.format(ident, picked_note))
                if not dry:
                    aggressor.bnote(picked_beacon['id'], picked_note)

@commands.command('cleanup')
def _(hours=80):
    cleanup(hours, dry=False)

@commands.command('cleanup-dryrun')
def _(hours=80):
    cleanup(hours, dry=True)

# Prune dead beacons.
@commands.command('prune-dead')
def _():
    prune_dead()

# Prune beacons older than :hours:
@commands.command('prune-old')
def _(hours=100):
    prune_old(int(hours))

@commands.command('companies')
def _():
    # collect beacons by company
    by_company = collections.defaultdict(list)
    for beacon in aggressor.beacons():
        if beacon['note'] and beacon['note'] != 'killing':
            parts = beacon['note'].split()
            company = parts[0]
            subnote = ' '.join(parts[1:])

            beacon['subnote'] = subnote
            by_company[company].append(beacon)

    for company, beacons in by_company.items():
        aggressor.println('{}:'.format(company))
        for beacon in beacons:
            aggressor.println('  - {}@{} {}'.format(beacon['user'], beacon['computer'], beacon['note']))
        aggressor.println()
