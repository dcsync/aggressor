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
from pycobalt.helpers import powershell_quote

def import_av_logs(bid):
    """
    Import AVLogs.ps1
    """

    aggressor.bpowershell_import(bid, utils.basedir('powershell/AVLogs.ps1'))

@aliases.alias('mcafee', 'Get McAfee logs')
def _(bid):
    import_av_logs(bid)
    aggressor.bpowerpick(bid, 'Get-McafeeLogs')

def edr_list():
    """
    Get list of EDR products.

    :return: Dictionary with driver name as key and description as value
    """

    edr_file = utils.basedir('resources/edr.txt')

    edrs = {}
    with open(edr_file, 'r') as fp:
        for line in fp:
            driver, name = line.split('\t')
            driver = driver.lower().strip()
            edrs[driver] = name.strip()
    return edrs

@aliases.alias('edr', 'Find EDR products')
def _(bid):
    drivers_dir = r'C:\Windows\System32\drivers'

    def ls_callback(bid, folder, content):
        edrs = edr_list()

        files = helpers.parse_ls(content)
        finds = set()
        for f in files:
            name = f['name'].lower()
            if name in edrs:
                finds.add(edrs[name])

        if finds:
            for find in finds:
                aggressor.blog2(bid, 'Found EDR product: {}'.format(find))
        else:
            aggressor.blog2(bid, 'No EDR products found')

    aggressor.btask(bid, 'Tasking beacon to find EDR products')
    aggressor.bls(bid, drivers_dir, ls_callback)

