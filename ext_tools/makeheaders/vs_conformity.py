#!/usr/bin/env python
# SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0

import re
import sys
from pprint import pprint

global my_file_loc

def repl_line(match):

    if "/mnt/c" in match.group("file")[:10]:
        ret = match.group("file").replace("/mnt/c","C:")
    elif "/mnt/d" in match.group("file")[:10]:
        ret = match.group("file").replace("/mnt/d","D:")
    else:
        ret = my_file_loc + match.group("file")

   # ret = ret .replace("/","\\")
    line_no1 = match.group("line_no")
    line_no2 = match.group("line_no2")

    if line_no1:
        ret += "(%s,%s)"%(line_no1,line_no2 if line_no2 else "0")
    else:
        ret += "(0,0)"

    return ret

if __name__ == "__main__":

    import argparse
    parser = argparse.ArgumentParser(description='Create VS2017 conform (sort of...) output from scons')
    parser.add_argument('source',   type=argparse.FileType('r'),
                                    nargs='?',
                                    default=sys.stdin,
                                    help='file/stream to parse. Default is stdin')
    parser.add_argument('--file_loc',
                                nargs='?',
                                default="",
                                help='prefix for file replacements')

    args = parser.parse_args()
    my_file_loc = args.file_loc

    content = args.source.read()

    #content = content.replace("\\","/")
    regex = re.compile("((?P<file>[a-zA-Z0-9_\-\/\\.]*\.[ch]):(?P<line_no>\d+):(?P<line_no2>\d*))", re.MULTILINE)
    content = re.sub(regex, repl_line, content)

    print(content)
    #1>/mnt/c/Users/simon/Repos/neuropil_v0.2_win/neuropil_v02/neuropil/examples/neuropil_test.c:40: undefined reference to `cr_expect'
    #1>C:\Users\simon\Repos\neuropil_v0.2_win\neuropil_v02\neuropil\\mnt\c\Users\simon\Repos\neuropil_v0.2_win\neuropil_v02\neuropil\examples\neuropil_test.c(53,0) undefined reference to `cr_expect'
