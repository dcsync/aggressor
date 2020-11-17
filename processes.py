import utils

# file containing process descriptions
elist_file = utils.basedir('resources/elist.txt')

def shadowbrokers_executables():
    """
    Get list of .exe descriptions from the Shadow Brokers leak.

    :return: Dictionary with executable name as key and description as value
    """

    apps = {}
    with open(elist_file, 'r') as fp:
        for line in fp:
            exe, desc = line.split('\t')
            exe = exe.lower().strip()
            apps[exe] = desc.strip()

    return apps

browsers = (
    'chrome',
    'chromium',
    'firefox',
    'iexplore',
    'MicrosoftEdge',
    'opera'
)

wallets = (
    # bitcoin
    'electrum'

    # decred
    'dcrd', 'decrediton', 'dcrwallet',
)

process_descriptions = shadowbrokers_executables()
