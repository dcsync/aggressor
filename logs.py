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

def convert_time(time):
    """
    Convert data model time to pretty time
    """

    return datetime.datetime.utcfromtimestamp(int(str(time)[:-3])).strftime('%Y-%m-%d %H:%M:%S')

def split_output(output):
    """
    Split up a piece of beacon output based on the [+] prefixes.
    """

    lines = output.splitlines()
    ret = []
    current = None
    for line in lines:
        if not current:
            current = line + '\n'

        if line.startswith('[*]') or line.startswith('[+]') or line.startswith('[!]'):
            if current:
                ret.append(current)
            current = line + '\n'
        else:
            current += line + '\n'

    return ret

# Grep keystrokes for a regex
@commands.command('grep-keystrokes')
def _(regex):
    found = False
    engine.message("Searching keystrokes for '{}'".format(regex))
    for frame in aggressor.data_query('keystrokes'):
        data = frame['data']
        bid = frame['bid']
        time = convert_time(frame['when'])
        beacon = '{}@{}'.format(aggressor.beacon_info(bid, 'user'), aggressor.beacon_info(bid, 'computer'))

        for line in data.splitlines():
            if re.search(regex, line, re.IGNORECASE):
                engine.message("Found keystroke matching '{}' from {} at {}: {}".format(regex, beacon, time, line))
                found = True

    if not found:
        engine.error("Didn't find any keystrokes containing '{}'".format(regex))

def parse_log(frame):
    """
    Parse a beacon log entry frame.

    :param frame: Log entry
    :return: {bid, type, user, data, time}
    """

    log = {}

    log['type'] = frame[0]
    log['bid'] = frame[1]
    if log['type'] == 'beacon_input':
        log['user'] = frame[2]
        log['data'] = frame[3]
        log['time'] = convert_time(frame[4])
    elif log['type'] == 'beacon_indicator':
        log['user'] = frame[2]
        log['data'] = frame[3]
        log['time'] = convert_time(frame[4])
    else:
        log['data'] = frame[2]
        log['time'] = convert_time(frame[3])

    return log

def get_logs(out, bid=None, user=None, computer=None):
    """
    Get logs for a bid, user, or computer

    :param out: Output file
    :param bid: Bid to match
    :param user: User to match
    :param computer: Computer to match
    """

    finds = 0
    for frame in aggressor.data_query('beaconlog'):
        log = parse_log(frame)

        if log['type'] == 'beacon_indicator':
            # skip indicators
            continue

        matched = False

        # check user
        if user:
            log_user = aggressor.beacon_info(log['bid'], 'user')

            if log_user == user:
                matched = True

        # check computer
        if computer:
            log_computer = aggressor.beacon_info(log['bid'], 'computer')

            if log_computer == computer:
                matched = True

        # check bid
        if bid and log['bid'] == bid:
            matched = True

        if matched:
            # it's a match!
            finds += 1

            # -o/--out
            with open(out, 'a+') as fp:
                # fix line endings
                data = log['data'].replace('\r\n', '\n')

                # add user attribution
                if log['type'] == 'beacon_input':
                    data = '{}> {}'.format(user, data)
                
                # write timestamp
                fp.write('----- {} -----\n'.format(log['time']))
                fp.write(data + '\n\n')

    return finds

# Get logs for user or computer
@commands.command('logs')
def _(*args):
    parser = helpers.ArgumentParser(prog='logs', description='Get logs for a user or computer')
    parser.add_argument('-c', '--computer', help='Get logs for computer')
    parser.add_argument('-u', '--user', help='Get logs for user')
    parser.add_argument('out', help='Output file')
    try: args = parser.parse_args(args)
    except: return

    finds = get_logs(args.out, user=args.user, computer=args.computer)
    engine.message('Wrote {} log entries to: {}'.format(finds, args.out))

# Get logs for beacon
@aliases.alias('logs', 'Get logs for a beacon', 'See `logs -h`')
def _(bid, *args):
    parser = helpers.ArgumentParser(prog='logs', bid=bid, description='Get logs for a beacon')
    parser.add_argument('out', help='Output file')
    try: args = parser.parse_args(args)
    except: return

    finds = get_logs(args.out, bid=bid)
    aggressor.blog2(bid, 'Wrote {} log entries to: {}'.format(finds, args.out))

# Grep beacon logs for a regex
@commands.command('grep-logs')
def _(*args):
    parser = helpers.ArgumentParser(prog='grep-logs', description='Grep beacon logs for a regex')
    parser.add_argument('-o', '--out', help='Output file')
    parser.add_argument('-w', '--whole', action='store_true', help='Show whole output')
    parser.add_argument('regex', action='append', help='Search for regex')
    try: args = parser.parse_args(args)
    except: return

    for regex in args.regex:
        finds = 0
        engine.message("Searching beacon logs for '{}'".format(regex))
        for frame in aggressor.data_query('beaconlog'):
            output_type = frame[0]
            bid = frame[1]
            if output_type == 'beacon_input':
                user = frame[2]
                data = frame[3]
                time = convert_time(frame[4])
            else:
                data = frame[2]
                time = convert_time(frame[3])

            for log in split_output(data):
                if re.search(regex, log, re.IGNORECASE):
                    beacon = '{}@{}'.format(aggressor.beacon_info(bid, 'user'), aggressor.beacon_info(bid, 'computer'))

                    # -w/--whole
                    if args.whole:
                        output = data
                    else:
                        output = log

                    # -o/--out
                    if args.out:
                        with open(args.out, 'a+') as fp:
                            fp.write(output)
                    else:
                        engine.message("Found beacon log matching '{}' from {} at {}:\n{}".format(regex, beacon, time, output))

                    finds += 1

        if finds:
            if args.out:
                engine.message("Wrote {} finds containing '{}' to '{}'".format(finds, regex, args.out))
            else:
                engine.message("Found {} logs containing '{}'".format(finds, regex))
        else:
            engine.error("Didn't find any beacon logs containing '{}'".format(regex))

# Create a directoy containing all beacon logs, keystrokes, targets, sessions, credentials, and rsync scripts for syncing downloads and screenshots
@commands.command('sync')
def _(outdir=None):
    # directory structure:
    # <out>/
    #   targets
    #   sessions
    #   credentials
    #   downloads.sh
    #   screenshots.sh ?
    #   user@computer/
    #       beacon-<bid>-<date>.log
    #       keystrokes.log
    #       screenshots/ ?

    def listmap_to_tsv(outfile, data):
        out = ''

        # get keys
        keys = set()
        for item in data:
            keys += set(item.keys())
        keys = sorted(keys)
        out += '\t'.join(keys)

        # get data
        for item in data:
            out += '\t'.join([item[key] if key in item else '' for key in keys])

        return out

    def sync(outdir):
        # top level
        os.makedirs(outdir, exist_ok=True)

        # sessions
        with open('{}/sessions.tsv'.format(outdir), 'w+') as fp:
            data = aggressor.data_query('sessions')
            fp.write(listmap_to_tsv(data))

        # credentials
        with open('{}/credentials.tsv'.format(outdir), 'w+') as fp:
            data = aggressor.data_query('credentials')
            fp.write(listmap_to_tsv(data))

        # targets
        with open('{}/targets.tsv'.format(outdir), 'w+') as fp:
            data = aggressor.data_query('targets')
            fp.write(listmap_to_tsv(data))

        # weblog
        with open('{}/weblog.tsv'.format(outdir), 'w+') as fp:
            data = aggressor.data_query('weblog')
            fp.write(listmap_to_tsv(data))

        # TODO downloads script

        # match beacons with computers
        # TODO use sessions?
        beacons = {}
        for beacon in aggressor.beacons():
            beacons[beacon['bid']] = '{}@{}'.format(beacon['user'].lower(), beacon['computer'].lower())

        # TODO beacon logs

        # keystrokes
        for keystroke in aggressor.data_query('keystrokes'):
            data = keystroke['data']
            bid = keystroke['bid']
            time = convert_time(keystroke['when'])

            beacon_outdir = '{}/{}'.format(outdir, beacons[bid])
            outfile = '{}/keystrokes.log'.format(beacon_outdir, beacons[bid])
            os.makedirs(beacon_outdir, exist_ok=True)
            with open(outfile, 'a+') as fp:
                fp.write(data + '\n')

        # screenshots
        for screenshot in aggressor.data_query('screenshots'):
            data = screenshot['data']
            bid = screenshot['bid']
            time = convert_time(screenshot['when'])

            screenshot_outdir = '{}/{}/screenshots'.format(outdir, beacons[bid])
            outfile = '{}/{}.png'.format(screenshot_outdir, time)
            os.makedirs(screenshot_outdir, exist_ok=True)
            with open(outfile, 'wb+') as fp:
                fp.write(data)

    if outdir:
        # use commandline directory
        sync(outdir)
    else:
        # prompt for directory
        aggressor.prompt_directory_open('Choose a folder', None, False, sync)

