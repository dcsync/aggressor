import sys
import utils
sys.path.insert(0, utils.basedir('pycobalt'))

import pycobalt.engine

# modules
import note_gui
import batch_gui

pycobalt.engine.loop()
