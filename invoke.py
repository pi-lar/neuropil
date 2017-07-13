#!/usr/bin/env python

import subprocess
import os

with open(os.devnull, 'w') as devnull:
  subprocess.Popen("./bin/neuropil_raspberry","-g","1","-b","3333", env={"DYLD_LIBRARY_PATH":".;build/lib","LD_LIBRARY_PATH":".;build/lib"}, stdin=devnull, stdout=devnull, stderr=devnull)
