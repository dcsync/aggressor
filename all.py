#!/usr/bin/env python3

import sys
import utils
sys.path.insert(0, utils.basedir('pycobalt'))

import pycobalt.engine

# config
import config

# modules
import aliases
import sharpgen
import exfil
import autoinject
import lateral
import privesc
import forensics
import av
import outlook
import creds
import network
import host
import logs
import ps
import powerview
import cleanup
import debug
import payloads

pycobalt.engine.loop()
