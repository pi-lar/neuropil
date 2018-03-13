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
parser.add_argument('-t', nargs='?', type=int, default=18, help='Count of threads to start for each node')
parser.add_argument('-oh', nargs='?', type=int, default=1, help='Host sysinfo config')
parser.add_argument('-oc', nargs='?', type=int, default=1, help='Clients sysinfo config')
parser.add_argument('-p', nargs='?', default="udp4", help='port type')
parser.add_argument('-s', nargs='?', default=1, help='Statistics View')
parser.add_argument('--path', nargs='?', default="./", help='Path to bin folder (ex.: "./bin/")')

args = parser.parse_args()


port_type = args.p
loglevel = args.l
publish_domain = args.pd
count = args.n -1
threads = args.t
sysinfo = args.oh
sysinfo_client = args.oc
statistics = args.s

autoclose = ""
if args.c :
    autoclose  = "; tmux kill-window"

server = libtmux.Server()

if args.k:
  if server.has_session("np"):
    server.find_where({ "session_name": "np" }).kill_session()

else:
  if not args.r or not server.has_session("np"):
    session= server.new_session("np", True)

    nb = session.new_window(attach=True, window_name="neuropil bootstraper")
    nb.attached_pane.send_keys(args.path + 'neuropil_node -b 3000 -t {} -p {}  -d {} -u {} -o {} -s {} {}'.format(
    threads, port_type, loglevel, publish_domain, sysinfo, statistics, autoclose))

    for i in range(count):
      print('start node {:3d}/{}'.format(i,count), end='\r')
      sys.stdout.flush()
      time.sleep(random.random())
      nn = session.new_window(attach=False, window_name="neuropil node {0:02d}".format(i))
      prefix = ''
      #prefix += 'perf record --call-graph dwarf -a --timestamp-filename '
      nn.attached_pane.send_keys(prefix + args.path + 'neuropil_node -b {} -t {} -p {} -o {} -j *:udp4:{}:3000 -d {} -s {} {}'.format(
      3000+i, threads, port_type, sysinfo_client, publish_domain, loglevel, statistics, autoclose))

  if not args.k:
    os.system('tmux attach -t np')