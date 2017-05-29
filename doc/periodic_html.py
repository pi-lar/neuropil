#!/usr/bin/python
import time
import subprocess

subprocess.call(["make","clean"])
while(True):
  subprocess.call(["make","html"])
  #time.sleep(1)


