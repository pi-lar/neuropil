#!/usr/bin/env python
from __future__ import print_function
import libtmux
import argparse
import os
import time
import random
import sys


parser = argparse.ArgumentParser(description='Start some neuropil nodes in screen sessions.')
parser.add_argument('-n', nargs='?', type=int, default=-6, help='Count of nodes to start')
parser.add_argument('-l', nargs='?', type=int, default=-3, help='LogLevel')
parser.add_argument('-pd', nargs='?', default="localhost", help='PublishDomain')
parser.add_argument('-c', action='store_true', help='Autoclose tmux window if node fails')
parser.add_argument('-r', action='store_true', help='Reconnect only')
parser.add_argument('--perf', action='store_true', help='Record Perf on Bootstrap')
parser.add_argument('-v', action='store_true', default=False, help='Valgrind prefix')
parser.add_argument('-vc', action='store_true', default=False, help='Valgrind Client prefix')
parser.add_argument('-vs', action='store_true', default=False, help='Valgrind Server prefix')
parser.add_argument('-g', action='store_true', default=False, help='GDB prefix')
parser.add_argument('-gc', action='store_true', default=False, help='GDB Client prefix')
parser.add_argument('-gs', action='store_true', default=False, help='GDB Server prefix')
parser.add_argument('-k', action='store_true', help='Kill all only')
parser.add_argument('-t', nargs='?', type=int, default=9, help='Count of threads to start for each node')
parser.add_argument('-tr', action='store_true', default=False, help='(Add) Random sleep timer during client startup')
parser.add_argument('-ts', nargs='?', type=int, default=-1, help='Sleep Timer (in ms) during client statup')
parser.add_argument('-oh', nargs='?', type=int, default=2, help='Host sysinfo config')
parser.add_argument('-oc', nargs='?', type=int, default=3, help='Clients sysinfo config')
parser.add_argument('-p', nargs='?', default=False, help='port type')
parser.add_argument('-ps', nargs='?', default=False, help='port type server')
parser.add_argument('-pc', nargs='?', default=False, help='port type clients')
parser.add_argument('-s', nargs='?', default=1, help='Statistics View')
parser.add_argument('-b', nargs='?', default=3000, help='Port to start from')
parser.add_argument('-j', nargs='?', default="", help='Join to ')
parser.add_argument('--path', nargs='?', default="", help='Path to build folder (shortcut for --bin_path and --lib_path)")')
parser.add_argument('--bin_path', nargs='?', default="./", help='Path to bin folder (ex.: "./bin/")')
parser.add_argument('--lib_path', nargs='?', default="", help='Path to lib folder (ex.: "./lib/")')
parser.add_argument('-hd', '--httpdomain', nargs='?', default="", help='Http domain specifier for client nodes')
parser.add_argument('--sd_prometheus', nargs='?', default="", help='Exports prometheus scrape data to')

args = parser.parse_args()

# propagate path config
if args.path:
    if not args.lib_path:
        args.lib_path = f'{args.path}/lib/'
    if args.bin_path == "./":
        args.bin_path = f'{args.path}/bin/'

# with valgrind attached only the console only view is practicable
if args.v or args.vs or args.vc:
    if args.s == 1:
        args.s = 0
        
if args.r and args.n < 0:
    args.n = 0
if args.n < 0:
    args.n *= -1

port = int(args.b)
port_type_server = args.p if args.p != False else args.ps if args.ps != False else "udp4"
port_type_client = args.p if args.p != False else args.pc if args.pc != False else "udp4"
loglevel = args.l
publish_domain = args.pd
threads = args.t
sysinfo = args.oh
sysinfo_client = args.oc
statistics = args.s
httpdomain = ""
if args.httpdomain != "":
  httpdomain = " -w " + args.httpdomain +" "

start_bootstrapper = True
join_client = " -j \"*:{}:{}:{}\"".format(port_type_server, publish_domain , port)
if args.j != "":
  join_client  = " -j {} ".format(args.j)
  start_bootstrapper = False
  args.r = True

count = args.n - start_bootstrapper

autoclose = ""
if args.c :
    autoclose  = "; tmux kill-window"

server = libtmux.Server()

session = server.find_where({ "session_name": "np" })
if args.k:
  if server.has_session("np"):
    session.kill_session()

else:
    if not args.r or not server.has_session("np"):
        session = server.new_session("np", True)
        
    windowName  = "neuropil bootstraper"
    if start_bootstrapper and not session.find_where({ "window_name": windowName }):
        nb = session.new_window(attach=True, window_name=windowName)
        prefix_bootstrap = ('valgrind --leak-check=full ' if args.v or args.vs else  ('gdb -ex run --args ' if args.g or args.gs else  ''))
        if args.perf:
            prefix_bootstrap = 'perf record --call-graph dwarf -a '
        if args.lib_path:
            nb.attached_pane.send_keys(f'export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:{args.lib_path}')
        nb.attached_pane.send_keys("  " + prefix_bootstrap + args.bin_path + f'neuropil_node -b {port} -t {threads} -p {port_type_server}  -d {loglevel} -u {publish_domain} -o {sysinfo} {httpdomain} -s {statistics} {autoclose} ')
        if args.v or args.vs:
            time.sleep(4)
        else:
            time.sleep(0.5)
    
    for i in range(count):
        windowName  = "neuropil node {0:05d}".format(i+port+start_bootstrapper)
        if not session.find_where({ "window_name": windowName }):
            print('start node {:3d}/{}'.format(i,count), end='\r')
            sys.stdout.flush()
            if args.tr or args.ts:
                args.ts = args.ts if args.ts != -1 else 10
                rand = random.random() if args.tr else 0
                time.sleep(rand+(args.ts/1000))
            nn = session.new_window(attach=False, window_name=windowName )
            node_port = port+i+start_bootstrapper
            node_http_port = port+i+start_bootstrapper+count
            if args.lib_path:
                nn.attached_pane.send_keys(f'export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:{args.lib_path}')
            nn.attached_pane.send_keys("  " + ('valgrind --leak-check=full ' if args.v or args.vc else  ('gdb -ex run --args ' if args.g or args.gc else  '')) + args.bin_path +
            f'neuropil_node -b {node_port} -u {publish_domain} -t {threads} -p {port_type_client} -o {sysinfo_client} -d {loglevel} {join_client} {httpdomain} -e {node_http_port} -s {statistics} {autoclose}')

    if not args.k:        
        if args.sd_prometheus:            
            with open(args.sd_prometheus,"w+") as file:
                file.write(f'[{{"targets": ["{args.httpdomain}:31415"')

                for i in range(count):
                    httpport = port+i+start_bootstrapper+count
                    file.write(f',"{args.httpdomain}:{httpport}"')

                file.write(']}]')

        os.system('tmux attach -t np')


