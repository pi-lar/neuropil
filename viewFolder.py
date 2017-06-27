#!/usr/bin/env python

import subprocess
import time
import os
import collections

while True:
  print '-----------------------------------------'
  extensions = collections.defaultdict(int)
  subprocess.call("ls -al",shell=True)
  for filename in os.listdir('.'):    
      extensions[os.path.splitext(filename)[1].lower()] += 1

  for key,value in extensions.items():
    print 'Extension: ', key, '\t', value, '\titems'
  time.sleep(1)

