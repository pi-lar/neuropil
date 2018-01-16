#!/usr/bin/env python

# Inserts a tracing log msg after every {  symbol

import os
import re
import io
startDir = "./src/"
# if empty all files are included
includeFiles =[];


# helper variable
currentGroup = ""

def replStart(m):
    global currentGroup
    org = m.group(0)
    ident = m.group(1).strip().replace('\n','')
    if(ident in ['enum','struct','[]']):
        return org
    else:
        return org + '\n    log_msg(LOG_TRACE'+currentGroup+', "start: ' + ident + '");'

def addTraceTo(txt):
    ret = re.sub(r"^(\s*([\w\*]+\s+[\w\*]+\([\n\w,\*\s]*\))\s*\n?\s*{)",replStart, txt,flags=re.MULTILINE)
    return ret;

def removeTraceFrom(txt):
    ret = re.sub(r"\s*log_msg\(LOG_TRACE[\| \w]*, \".*\"\);", "", txt)
    return ret;

for fileName in os.listdir(startDir):
    if fileName.endswith(".c"):
        if ((not includeFiles) or (fileName in includeFiles)):
            if(fileName == "np_http.c"):
                currentGroup = " | LOG_HTTP"
            elif(fileName == "np_key.c"):
                currentGroup = " | LOG_KEY"
            elif(fileName == "np_network.c"):
                currentGroup = " | LOG_NETWORK"
            elif(fileName == "np_route.c"):
                currentGroup = " | LOG_ROUTING"
            elif(fileName == "np_threads.c"):
                currentGroup = " | LOG_MUTEX"
            elif(fileName == "np_aaatoken.c"):
                currentGroup = " | LOG_AAATOKEN"
            elif(fileName == "np_message.c" or fileName == "np_messagepart.c"):
                currentGroup = " | LOG_MESSAGE"
            else:
                currentGroup = " | LOG_GLOBAL"

            filepath = os.path.join(startDir,fileName)
            file = io.open(filepath, mode="w+", encoding="utf-8")
            txt = file.read();
            txt = removeTraceFrom(txt)
            txt = addTraceTo(txt)            
            file.seek(0,0)
            file.write(txt)
            file.close()
