#!/usr/bin/env python

import subprocess
import os

with open(os.devnull, 'w') as devnull:
  subprocess.Popen("./bin/neuropil_hydra",env={"DYLD_LIBRARY_PATH":".;build/lib","LD_LIBRARY_PATH":".;build/lib"}, stdin=devnull, stdout=devnull, stderr=devnull)
