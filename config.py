import pycobalt.sharpgen
import pycobalt.aliases
import pycobalt.aggressor
import pycobalt.engine

import powerpick

#
# SharpGen settings
#

protections_net35 = {
    #'anti debug': None,
    #'anti dump': None,
    #'anti ildasm': None,
    #'anti tamper': None,

    #'constants': None,
    'ctrl flow': None,
    #'ctrl flow': {'mode': 'jump',
    #              'intensity': 30,
    #              'junk': 'true'},
    #'constants': {'mode': 'dynamic',
    #              'decoderCount': 20,
    #              'elements': 'SNPI',
    #              'cfg': 'true'},
    #'ctrl flow': {'mode': 'jump',
    #              'intensity': 30,
    #              'junk': 'true'},

    #'invalid metadata': None,
    #'ref proxy': None,
    'ref proxy': {#'mode': 'strong',
                  'encoding': 'expression',
                  'internal': 'true',
                  'typeErasure': 'true',
                  'depth': 5,
                  'initCount': 16},
    'rename': {'mode': 'ascii'},
    'resources': {'mode': 'dynamic'},
    #'typescramble': None,
}
protections_net40 = protections_net35

def set_dotnet(version):
    if version == 'net35':
        pycobalt.sharpgen.set_confuser_protections(protections_net35)
    else:
        pycobalt.sharpgen.set_confuser_protections(protections_net40)

    pycobalt.sharpgen.set_dotnet_framework(version)

# powerpick
powerpick.enable_custom_powerpick()

# sharpgen
set_dotnet('net35')
pycobalt.sharpgen.set_resources()
pycobalt.sharpgen.set_references()
#pycobalt.sharpgen.enable_cache()
pycobalt.sharpgen.set_using()

# quote replacement
pycobalt.aliases.set_quote_replacement('^')

# debug
#pycobalt.engine.enable_debug()
