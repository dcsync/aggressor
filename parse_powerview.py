#!/usr/bin/env python3

import re
import pprint

powerview = '/share/tools/powershell/PowerSploit/Recon/PowerView.ps1'
out = 'powerview_generated.py'

current_function = None
current_description = ''

# {function: description}
functions = {}
# {alias: function}
aliases = {}

for line in open(powerview, 'r'):
    function_match = re.match('function ([^ ]+)\s*{.*', line)
    alias_match = re.match('Set-Alias ([^ ]+) (.+)', line)
    if function_match:
        current_function = function_match.group(1)
    elif alias_match:
        alias = alias_match.group(1)
        function = alias_match.group(2)
        aliases[alias] = function
    elif current_description and line.strip() == '#>':
        functions[current_function] = current_description
        current_function = None
        current_description = ''
    elif line.strip() == '<#':
        pass
    elif current_function:
        current_description += line

print('writing {} functions and {} aliases to {}'.format(len(functions), len(aliases), out))

code = 'functions = ' + pprint.pformat(functions) + '\n\n' + \
       'aliases = ' + pprint.pformat(aliases)
open(out, 'w+').write(code)
