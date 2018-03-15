#!/usr/bin/env python
from __future__ import print_function
from colorama import init, Fore, Back, Style
import sys
import re
from pprint import pprint


init()

colors = [
Fore.RED                                  ,
Fore.GREEN                                ,
Fore.YELLOW                               ,
#Fore.BLUE                                 ,
Fore.MAGENTA                              ,
Fore.CYAN                                 ,
Fore.WHITE                                ,
Fore.RED     + Style.BRIGHT               ,
Fore.GREEN   + Style.BRIGHT               ,
Fore.YELLOW  + Style.BRIGHT               ,
#Fore.BLUE    + Style.BRIGHT               ,
Fore.MAGENTA + Style.BRIGHT               ,
Fore.CYAN    + Style.BRIGHT               ,
Fore.WHITE   + Style.BRIGHT               ,
Fore.GREEN                  + Back.RED    ,
Fore.YELLOW                 + Back.RED    ,
Fore.BLUE                   + Back.RED    ,
#Fore.MAGENTA                + Back.RED    ,
Fore.CYAN                   + Back.RED    ,
Fore.WHITE                  + Back.RED    ,
Fore.GREEN   + Style.BRIGHT + Back.RED    ,
Fore.YELLOW  + Style.BRIGHT + Back.RED    ,
Fore.BLUE    + Style.BRIGHT + Back.RED    ,
#Fore.MAGENTA + Style.BRIGHT + Back.RED    ,
Fore.CYAN    + Style.BRIGHT + Back.RED    ,
Fore.WHITE   + Style.BRIGHT + Back.RED    ,
Fore.RED                    + Back.GREEN  ,
#Fore.YELLOW                 + Back.GREEN  ,
Fore.BLUE                   + Back.GREEN  ,
Fore.MAGENTA                + Back.GREEN  ,
Fore.CYAN                   + Back.GREEN  ,
Fore.WHITE                  + Back.GREEN  ,
Fore.RED     + Style.BRIGHT + Back.GREEN  ,
#Fore.YELLOW  + Style.BRIGHT + Back.GREEN  ,
Fore.BLUE    + Style.BRIGHT + Back.GREEN  ,
Fore.MAGENTA + Style.BRIGHT + Back.GREEN  ,
#Fore.CYAN    + Style.BRIGHT + Back.GREEN  ,
#Fore.WHITE   + Style.BRIGHT + Back.GREEN  ,
Fore.RED                    + Back.YELLOW ,
Fore.GREEN                  + Back.YELLOW ,
Fore.BLUE                   + Back.YELLOW ,
Fore.MAGENTA                + Back.YELLOW ,
Fore.CYAN                   + Back.YELLOW ,
#Fore.WHITE                  + Back.YELLOW ,
Fore.RED     + Style.BRIGHT + Back.YELLOW ,
Fore.GREEN   + Style.BRIGHT + Back.YELLOW ,
Fore.BLUE    + Style.BRIGHT + Back.YELLOW ,
Fore.MAGENTA + Style.BRIGHT + Back.YELLOW ,
Fore.CYAN    + Style.BRIGHT + Back.YELLOW ,
#Fore.WHITE   + Style.BRIGHT + Back.YELLOW ,
Fore.RED                    + Back.BLUE   ,
Fore.GREEN                  + Back.BLUE   ,
Fore.YELLOW                 + Back.BLUE   ,
#Fore.MAGENTA                + Back.BLUE   ,
#Fore.CYAN                   + Back.BLUE   ,
Fore.WHITE                  + Back.BLUE   ,
Fore.RED     + Style.BRIGHT + Back.BLUE   ,
Fore.GREEN   + Style.BRIGHT + Back.BLUE   ,
Fore.YELLOW  + Style.BRIGHT + Back.BLUE   ,
#Fore.MAGENTA + Style.BRIGHT + Back.BLUE   ,
#Fore.CYAN    + Style.BRIGHT + Back.BLUE   ,
#Fore.WHITE   + Style.BRIGHT + Back.BLUE   ,
Fore.RED                    + Back.MAGENTA,
Fore.GREEN                  + Back.MAGENTA,
Fore.YELLOW                 + Back.MAGENTA,
Fore.BLUE                   + Back.MAGENTA,
Fore.CYAN                   + Back.MAGENTA,
Fore.WHITE                  + Back.MAGENTA,
Fore.RED     + Style.BRIGHT + Back.MAGENTA,
Fore.GREEN   + Style.BRIGHT + Back.MAGENTA,
Fore.YELLOW  + Style.BRIGHT + Back.MAGENTA,
Fore.BLUE    + Style.BRIGHT + Back.MAGENTA,
Fore.CYAN    + Style.BRIGHT + Back.MAGENTA,
#Fore.WHITE   + Style.BRIGHT + Back.MAGENTA,
Fore.RED                    + Back.CYAN   ,
Fore.GREEN                  + Back.CYAN   ,
Fore.YELLOW                 + Back.CYAN   ,
#Fore.BLUE                   + Back.CYAN   ,
#Fore.MAGENTA                + Back.CYAN   ,
Fore.WHITE                  + Back.CYAN   ,
Fore.RED     + Style.BRIGHT + Back.CYAN   ,
Fore.GREEN   + Style.BRIGHT + Back.CYAN   ,
Fore.YELLOW  + Style.BRIGHT + Back.CYAN   ,
#Fore.BLUE    + Style.BRIGHT + Back.CYAN   ,
#Fore.MAGENTA + Style.BRIGHT + Back.CYAN   ,
#Fore.WHITE   + Style.BRIGHT + Back.CYAN   ,
Fore.RED                    + Back.WHITE  ,
Fore.GREEN                  + Back.WHITE  ,
#Fore.YELLOW                 + Back.WHITE  ,
Fore.BLUE                   + Back.WHITE  ,
Fore.MAGENTA                + Back.WHITE  ,
Fore.CYAN                   + Back.WHITE  ,
Fore.RED     + Style.BRIGHT + Back.WHITE  ,
Fore.GREEN   + Style.BRIGHT + Back.WHITE  ,
#Fore.YELLOW  + Style.BRIGHT + Back.WHITE  ,
#Fore.BLUE    + Style.BRIGHT + Back.WHITE  ,
Fore.MAGENTA + Style.BRIGHT + Back.WHITE  ,
Fore.CYAN    + Style.BRIGHT + Back.WHITE
]

threads  = {'index':0}
files    = {'index':0}
uuids    = {'index':0}
subjects = {'index':30}
dhkeys   = {'index':70}
level    = {'index':7, 'ERROR':Fore.RED,'WARN':Fore.YELLOW,'INFO':Fore.WHITE,'DEBUG':Fore.CYAN}

def colorize(arr, key):
  ret = ""
  if key in arr:
      ret = arr[key]
  else:
    arr['index'] = (arr['index']+1) % len(colors)
    ret = arr[key] = colors[arr['index']]
  return "{}{}{}{}".format(ret, key, Style.RESET_ALL, Style.RESET_ALL)

def msgColorizer(msg):
    ret = msg
    for match in re.findall("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", ret):
        ret = ret.replace(match,colorize(uuids,match))
    for match in re.findall("[0-9a-f]{64}", ret):
        ret = ret.replace(match,colorize(dhkeys,match))
    for match in re.findall("_np.subj:[A-Z\._]+", ret):
        ret = ret.replace(match,colorize(subjects,match))

    return ret

for line in sys.stdin:
    data = line.split(None, 6)
    #pprint(data)
    #continue;
    print(colorize(files, data[0]), end=' ') #neuropil_node_3000.log:2018-02-28
    print(data[1], end=' ') #09:17:42.124759
    print(colorize(threads,data[2]), end=' ') #140538018199296
    print(data[3], end=' ') #src/np_dendrit.:241
    print(data[4], end=' ') #_np_in_received
    print(colorize(level, data[5].replace("_","")))#_WARN__
    print(str.strip(msgColorizer(data[6]))) #message resend count (32) too high, dropping message (part) 3a823a5e-05cf-5cbe-935b-4b978a7f87f4 / _NP.NODES.UPDATE

