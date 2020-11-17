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
import pycobalt.sharpgen as sharpgen
from pycobalt.helpers import powershell_quote

def pretty_short_time(milli, decimalSeconds=False):
    """
    Convert milliseconds to a pretty short time format. Examples:

      400 -> 400ms
      1000 -> 1s
      1110 -> 1.11s
      60 * 1100 -> 1m:6s
      60 * 60 * 2100 -> 2h:6m
      24 * 60 * 60 * 1500 -> 1d:12h
    """

    parts = 1

    # seconds/milli
    seconds = int(milli / 1000)
    milli %= 1000
    if seconds: parts += 1

    # minutes/seconds
    minutes = int(seconds / 60)
    seconds %= 60
    if minutes: parts += 1

    # hours/minutes
    hours = int(minutes / 60)
    minutes %= 60
    if hours: parts += 1

    # days/hours
    days = int(hours / 24)
    hours %= 24
    if days: parts += 1

    if parts == 1:
        return '{}ms'.format(milli)
    if parts == 2:
        if decimalSeconds and milli:
            dec = '.{}'.format(str(int(milli/10)).rstrip('0'))
            if dec == '.': dec = ''
        else: dec =''
        return '{}{}s'.format(seconds, dec)
    elif parts == 3:
        return '{}m:{}s'.format(minutes, seconds)
    elif parts == 4:
        return '{}h:{}m'.format(hours, minutes)
    elif parts == 5:
        return '{}d:{}h'.format(days, hours)

def parse_pretty_short(value, default_milli=False):
    """
    Parse pretty short time format.

    The pretty short time format looks like this: 9d:8h:7m:6s:5ms
    That represents: 9 days, 8 hours, 7 minutes, 6 seconds, and 5 milliseconds

    :param value: Pretty short time value
    :return: Dictionary containing {days, hours, minutes, seconds, milli}
    """

    ret = {
        'days': 0,
        'hours': 0,
        'minutes': 0,
        'seconds': 0,
        'milli': 0,
    }

    for part in value.split(':'):
        part = part.strip()
        if part.endswith('ms'):
            ret['milli'] += int(part[:-2])
        elif part.endswith('d'):
            ret['days'] += float(part[:-1])
        elif part.endswith('h'):
            ret['hours'] += float(part[:-1])
        elif part.endswith('m'):
            ret['minutes'] += float(part[:-1])
        elif part.endswith('s'):
            ret['seconds'] += float(part[:-1])
        else:
            if default_milli:
                ret['milli'] += int(part)
            else:
                ret['seconds'] += int(part)

    return ret

def pretty_short_to_milli(value, default_milli=False):
    """
    Convert pretty short time format to milliseconds

    :param value: Pretty short time value
    :return: Time in milliseconds
    """

    items = parse_pretty_short(value, default_milli=default_milli)
    days = items['days']
    hours = items['hours']
    minutes = items['minutes']
    seconds = items['seconds']
    milli = items['milli']
    hours += days * 24
    minutes += hours * 60
    seconds += minutes * 60
    milli += int(seconds * 1000)

    return milli

def pretty_short_to_seconds(value):
    """
    Convert pretty short time format to seconds

    :param value: Pretty short time value
    :return: Time in seconds
    """

    return float(pretty_short_to_milli(value)) / 1000.0

def sleep(bid, value, jitter=30):
    """
    Tell a beacon to sleep for a certain amount of time

    The pretty short time format looks like this: 9d:8h:7m:6s:5ms
    That represents: 9 days, 8 hours, 7 minutes, 6 seconds, and 5 milliseconds

    Plain numbers are converted to seconds.

    :param bid: Beacon
    :param value: Pretty time value
    :param jitter: Jittery percentage (default: 30)
    """

    sleep_time = int(pretty_short_to_seconds(value))
    jitter = int(jitter)
    jitter_factor = sleep_time * (jitter / 100)
    max_sleep = sleep_time + jitter_factor
    min_sleep = sleep_time - jitter_factor
    pretty_max = pretty_short_time(max_sleep * 1000)
    pretty_min = pretty_short_time(min_sleep * 1000)

    if sleep_time:
        aggressor.btask(bid, 'Tasked beacon to sleep for between {} and {}'.format(pretty_min, pretty_max))
    else:
        aggressor.btask(bid, 'Tasked beacon to be interactive')

    aggressor.bsleep(bid, sleep_time, jitter, silent=True)

def pause(bid, value):
    """
    Tell a beacon to pause for a certain amount of time

    The pretty short time format looks like this: 9d:8h:7m:6s:5ms
    That represents: 9 days, 8 hours, 7 minutes, 6 seconds, and 5 milliseconds

    Plain numbers are converted to seconds.

    :param bid: Beacon
    :param value: Pretty time value
    :param jitter: Jittery percentage (default: 30)
    """

    sleep_time = pretty_short_to_milli(value)
    pretty_time = pretty_short_time(sleep_time)

    aggressor.btask(bid, 'Tasked beacon to pause for {}'.format(pretty_time))
    aggressor.bpause(bid, sleep_time)
