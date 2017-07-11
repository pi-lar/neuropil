#!/usr/bin/env python

import subprocess
import os

with open(os.devnull, 'w') as devnull:
  subprocess.Popen("./bin/neuropil_hydra",stdin=devnull, stdout=devnull, stderr=devnull)
