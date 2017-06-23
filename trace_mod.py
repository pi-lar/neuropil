#!/usr/bin/env python

# Inserts a tracing log msg after/before every { and } symbol
# if not already present

import os
import re
from pathlib2 import Path

startDir = "./src/"


stack = []
currFile = ''
ignoreFindings = []
counter =0

def replStart(m):
    global stack
    global counter
    global ignoreFindings
    counter += 1
    org = m.group(0)
    ident = m.group(1).strip().replace('\n','')
    if(ident in ['enum','struct','[]']):
        ignoreFindings.append(counter)
        return org
    else:
        print ident
        stack.append(ident)
        return org + '\n    log_msg(LOG_TRACE, "start: ' + ident + '");'

def replEnd(m):
    global stack
    global counter
    global currFile
    global ignoreFindings
    counter += 1

    if not stack:
        print "error on " + currFile + ". Wrong {} count " + str(counter)
        exit(1)
    else:
        if(counter in ignoreFindings):
            ignoreCounter-=1
            return "}"
        else:
            ident = stack.pop()
            return '    log_msg(LOG_TRACE, "end: ' + ident + '");\n}'


def scanFile(fileToScan):
    global stack
    global counter
    global ignoreFindings
    global currFile
    stack =[]
    ignoreFindings=[]

    filepath = os.path.join(startDir,fileToScan)
    print "editing " + filepath

    currFile = filepath
    txt = Path(filepath).read_text().encode('utf-8')
    counter = 0
    txt = re.sub(r"^(\s*([\w\*]+\s+[\w\*]+\([\n\w,\*\s]*\))\s*\n?\s*{)",replStart, txt,flags=re.MULTILINE)
    #counter = 0
    #txt = re.sub(r"\}", replEnd,  txt)
    file = open(filepath, 'w')
    file.write(txt)
    #print txt
    file.close()

for file in os.listdir(startDir):
    if file.endswith(".c"):
        scanFile(file)
