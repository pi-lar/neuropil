#!/usr/bin/env python
import os
from pprint import pprint
import argparse

# Prerequisite for a testbed system:
# - tmux
# - clang
# - git
# - virtualenv
# - python3


parser = argparse.ArgumentParser(description='Start some neuropil nodes in screen sessions.')
parser.add_argument('--bootstrapper', nargs='?', default=False, help='Bootstrap connection string')
parser.add_argument('-b', '--branch', nargs='?', default="develop", help='Branch to test')
parser.add_argument('-du', '--default_user', nargs='?', default="localadmin", help='Default user to use to start nodes on remote machines')


args = parser.parse_args()


branch = args.branch

defaults = {"user": args.default_user,  "build":True, "bin_dir":"bin", "work_dir":"~/neuropil_testbed", "desc":"", "ip":""}
locations = [
    # Add new testbed systems here: 
    dict(defaults,**{"desc":"Ubuntu",    "ip":"192.168.30.200"}),
    dict(defaults,**{"desc":"FreeBSD",   "ip":"192.168.30.201"}),
    dict(defaults,**{"desc":"OSX",       "ip":"192.168.40.46", "user":"Development"}),
    #dict(defaults,**{"desc":"Raspberry", "ip":"192.168.40.29", "user":"pi-lar"     }),
]

if not args.bootstrapper:	
    bootstrap_string = input("Bootstrapper (with hash):") 
else:	
    bootstrap_string = args.bootstrapper

bootstrap_string_w = "*" + bootstrap_string[64:]

options_progs = [    
      ("node ", "node  -d -1 "),
      ("hydra", "hydra -d -1 -n 6 -z 3600 -k 25200 "),
      ("cloud", "cloud -d -1 "),
    ]
options_threads = [
      ("singlethreaded", "-t 0"),
      ("multithreaded ", "-t 3"),
    ]
options_jointype = [
      ("hash    ",     "-j {bootstrap_string}".format(**locals())),
      ("wildcard", "-j {bootstrap_string_w}".format(**locals())),
    ]

options_protocol = [
    'udp4',
    'tcp4',
    'udp6',
    'tcp6',
]

build_commands = [
    "deactivate",
    #"rm -fr {d[work_dir]}",
    "mkdir -p {d[work_dir]}",
    "cd {d[work_dir]}",
    "echo WorkDir:", 
    "pwd",
    "grep ^git.in.pi-lar.net ~/.ssh/known_hosts || ssh-keyscan git.in.pi-lar.net >> ~/.ssh/known_hosts 2>/dev/null",
    "git clone git@git.in.pi-lar.net:pi-lar/neuropil_lib.git --branch {branch}  --single-branch -q . || (git fetch && git checkout {branch} && git pull)",
    "python3 -m venv env",
    "source ./env/bin/activate",
    "pip list --outdated --format=freeze | grep -v ^\\-e | cut -d = -f 1  | xargs -n1 pip install -U",
    "pip install scons"
    ,"scons debug=2 test=0"
    #,"scons debug=1 test=0"
    #,"scons release=1 test=0"
]

# generate option permutations
total_nodes_startet = 0
total_nodes_requested = 0
for d in locations: 
    for attr, value in d.items():
        if isinstance(d[attr], str):
            d[attr] = d[attr].format(**d)

    start_commands = []    
    for option_prog_s, option_prog  in options_progs:
        option_prog = option_prog%locals()
        for option_jointype_s, option_jointype in options_jointype:
            for option_thread_s, option_thread in options_threads:
                for option_protocol in options_protocol:
                    command_desc = "{option_prog_s} {option_thread_s} {option_protocol} {option_jointype_s}".format(**locals())
                    command_call = "./{d[bin_dir]}/neuropil_{option_prog} -u {d[ip]} {option_thread} -p {option_protocol} {option_jointype}".format(**locals())
                    start_commands += [(command_call,command_desc)]
 

    commands_prefix = [
        "cd {d[work_dir]}",
        "tmux start-server",
        "tmux kill-session -t neuropil_E2E_tests",
        "tmux set -g remain-on-exit on",
        "tmux new-session -d -s neuropil_E2E_tests -n neuropil_E2E_test",
        ]
    
    if d["build"]:
        commands_prefix = commands_prefix + build_commands
    command_str = ";".join(commands_prefix).format(**locals())+";"	
    for i, pack in enumerate(start_commands):        
        start_command,start_command_desc = pack
        command_str += 'tmux new-window -ad -t neuropil_E2E_tests -n np_{i};'.format(**locals())
        command_str += 'tmux send-keys      -t neuropil_E2E_tests:np_{i} "export LD_LIBRARY_PATH=build/lib:$LD_LIBRARY_PATH";'.format(**locals())
        command_str += 'tmux send-keys      -t neuropil_E2E_tests:np_{i} C-m;'.format(**locals())
        command_str += 'tmux send-keys      -t neuropil_E2E_tests:np_{i} "{start_command}";'.format(**locals())
        command_str += 'tmux send-keys      -t neuropil_E2E_tests:np_{i} C-m;'.format(**locals())
        command_str += 'echo "started np_{i:0>3d}:{d[ip]} => {start_command_desc}";'.format(**locals())		
        total_nodes_requested = total_nodes_requested + 1
    
    command_str = command_str.replace('"','\\"')
    cmd = "ssh -A {d[user]}@{d[ip]} 'bash -l -c \"{command_str}\"' ".format(**locals())    
    #print(cmd)
    print("Starting commands on {d[user]}@{d[ip]}".format(**locals()))
    result = os.system(cmd)
    if result == 0:
        total_nodes_startet = total_nodes_startet + i
    print("Exec on {d[user]}@{d[ip]} = {result}".format(**locals()))

print("Started {total_nodes_startet}/{total_nodes_requested} Nodes".format(**locals()))	