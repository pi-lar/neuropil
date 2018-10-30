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
parser.add_argument('--bootstrapper', nargs='?', default="80e4e9b9f6986ffb5175f6813456da0175b4b67ff41dc419430182fec4fe70aa:tcp6:demo.neuropil.io:3141", help='Bootstrap connection string')
parser.add_argument('-b', '--branch', nargs='?', default="develop", help='Branch to test')
parser.add_argument('-du', '--default_user', nargs='?', default="simonklampt", help='Default user to use to start nodes on remote machines')



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

bootstrap_string   = args.bootstrapper
bootstrap_string_w = "*" + bootstrap_string[64:]

options_progs = [    
      ("node",  "node"),
      ("hydra", "hydra -n 1"),
      ("cloud", "cloud "),
    ]
options_threads = [
      ("singlethreaded", "-t 0"),
      ("multithreaded", "-t 3"),
    ]
options_jointype = [
      ("hash",     "-j %(bootstrap_string)s"),
      ("wildcard", "-j %(bootstrap_string_w)s"),
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
    "pip list --outdated --format=freeze | grep -v ^\-e | cut -d = -f 1  | xargs -n1 pip install -U",
    "pip install scons",
    "scons debug=1 test=0"
]

# generate option permutations
for d in locations: 
    for attr, value in d.items():
        if isinstance(d[attr], str):
            d[attr] = d[attr].format(**d)


    start_commands = []    
    for option_prog_s,option_prog  in options_progs:
        option_prog = option_prog%locals()
        for option_jointype_s,option_jointype in options_jointype:
            for option_thread_s,option_thread in options_threads:
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
        command_str += 'echo "started np_{i}:{d[ip]} => {start_command_desc}";'.format(**locals())
    
    command_str = command_str.replace('"','\\"')
    cmd = "ssh -A {d[user]}@{d[ip]} 'bash -l -c \"{command_str}\"' ".format(**locals())    
    print(cmd);
    print("Starting commands on {d[user]}@{d[ip]}".format(**locals()))
    result = os.system(cmd)
    print("Exec on {d[user]}@{d[ip]} = {result}".format(**locals()))
    