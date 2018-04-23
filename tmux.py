#!/usr/bin/env python
from __future__ import print_function
import libtmux
import argparse
import os
import time
import random
import sys


parser = argparse.ArgumentParser(description='Start some neuropil nodes in screen sessions.')
parser.add_argument('-n', nargs='?', type=int, default=6, help='Count of nodes to start')
parser.add_argument('-l', nargs='?', type=int, default=-3, help='LogLevel')
parser.add_argument('-pd', nargs='?', default="localhost", help='PublishDomain')
parser.add_argument('-c', action='store_true', help='Autoclose tmux window if node fails')
parser.add_argument('-r', action='store_true', help='Reconnect only')
parser.add_argument('-k', action='store_true', help='Kill all only')
parser.add_argument('-t', nargs='?', type=int, default=12, help='Count of threads to start for each node')
parser.add_argument('-oh', nargs='?', type=int, default=1, help='Host sysinfo config')
parser.add_argument('-oc', nargs='?', type=int, default=1, help='Clients sysinfo config')
parser.add_argument('-p', nargs='?', default="udp4", help='port type')
parser.add_argument('-s', nargs='?', default=1, help='Statistics View')
parser.add_argument('-b', nargs='?', default=3000, help='Port to start from')
parser.add_argument('-j', nargs='?', default="", help='Join to ')
parser.add_argument('--path', nargs='?', default="./", help='Path to bin folder (ex.: "./bin/")')
parser.add_argument('--httpdomain_client', nargs='?', default="", help='Http domain specifier for client nodes')

args = parser.parse_args()


port = int(args.b)
port_type = args.p
loglevel = args.l
publish_domain = args.pd
threads = args.t
sysinfo = args.oh
sysinfo_client = args.oc
statistics = args.s
httpdomain_client = ""
if args.httpdomain_client != "":
  httpdomain_client = " -w " + args.httpdomain_client +" "

start_bootstrapper = True
join_client = " -j *:udp4:{}:{}".format(publish_domain , port)
if args.j != "":
  join_client  = " -j {} ".format(args.j)
  start_bootstrapper = False
  args.r = True

count = args.n - start_bootstrapper

autoclose = ""
if args.c :
    autoclose  = "; tmux kill-window"

server = libtmux.Server()

if args.k:
  session = server.find_where({ "session_name": "np" })
  if server.has_session("np"):
    session.kill_session()
else:
  if not args.r or not server.has_session("np"):
    session = server.new_session("np", True)

    windowName  = "neuropil bootstraper"
    if start_bootstrapper and not server.find_where({ "window_name": windowName }):
        nb = session.new_window(attach=True, window_name=windowName)
        nb.attached_pane.send_keys(args.path + './bin/neuropil_node -b {} -t {} -p {}  -d {} -u {} -o {} -s {} {}'.format(
            port, threads, port_type, loglevel, publish_domain, sysinfo, statistics, autoclose))

    for i in range(count):
        windowName  = "neuropil node {0:05d}".format(i+port+start_bootstrapper)
        if not session.find_where({ "window_name": windowName }):
            print('start node {:3d}/{}'.format(i,count), end='\r')
            sys.stdout.flush()
            time.sleep(random.random())
            nn = session.new_window(attach=False, window_name=windowName )
            prefix = ''
            #prefix += 'perf record --call-graph dwarf -a --timestamp-filename '
            nn.attached_pane.send_keys(prefix + args.path + './bin/neuropil_node -b {} -u {} -t {} -p {} -o {} -d {} {} {} -s {} {}'.format(
            port+i+start_bootstrapper,publish_domain, threads, port_type, sysinfo_client, loglevel, join_client, httpdomain_client, statistics, autoclose))
    os.system('tmux attach -t np')    
  
  if args.r:
    os.system('tmux attach -t np')
