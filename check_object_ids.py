#!/usr/bin/env python
import os
import re
import sys
import pprint
from pathlib2 import Path


startDir = '.'

rx = re.compile(r"^((.* _?(Creating|Deleting)_? object of type \"(.*)\".*) on (.*))$", flags=re.MULTILINE)

for fileName in os.listdir(startDir):
    if fileName.endswith(".log"):
        dictResult = {}
        i=0
        filepath = os.path.join(startDir,fileName)
        sys.stdout.write("scanning: " + filepath+" ")
        txt = Path(filepath).read_text().encode('utf-8')
        if txt:
            for entry in re.findall(rx, txt):
                i += 1
                obj_id = entry[4]
                #print(obj_id)
                if dictResult.has_key(obj_id):
                    del dictResult[obj_id]
                else:
                    dictResult.setdefault(obj_id, entry)

        #continue
        for k in dictResult:
            print(dictResult[k][0])

        print("%s: created items: %d non removed objects: %d" %(fileName,i/2 + len(dictResult.keys()),len(dictResult.keys()) ))
        print("")
