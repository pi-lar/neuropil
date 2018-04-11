#!/usr/bin/env python
import re
import sys
from pprint import pprint

global my_file_loc

def repl_line(match):

    ret = my_file_loc + match.group("file").replace("/","\\")
    line_no1 = match.group("line_no")
    line_no2 = match.group("line_no2")

    if line_no1:
        ret += "(%s,%s)"%(line_no1,line_no2)

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
    pprint(args.file_loc)
    my_file_loc = args.file_loc#.replace("\\","\\\\")[:-1]
    pprint(my_file_loc)

    content = args.source.read()

    content = content.replace("\\","/")
    regex = re.compile("((?P<file>[a-zA-Z0-9_\-\/]*\.[ch]):(?P<line_no>\d+):(?P<line_no2>\d*))", re.MULTILINE)
    content = re.sub(regex, repl_line, content)

    print(content)
