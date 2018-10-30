#!/usr/bin/env python
import os
from pprint import pprint
# Prerequisite for a testbed system:
# - tmux
# - clang
# - git
# - virtualenv
# - python3

branch = "develop"      # Define the branch/tag/commit to test
branch = "fb_testbed"

defaults = {"user": "simonklampt",  "build":True, "bin_dir":"bin", "work_dir":"~/neuropil_testbed", "desc":"", "ip":""}
locations = [
    # Add new testbed systems here: 
    dict(defaults,**{"desc":"Ubuntu",    "ip":"192.168.30.200"}),
    dict(defaults,**{"desc":"FreeBSD",   "ip":"192.168.30.201"}),
    dict(defaults,**{"desc":"OSX",       "ip":"192.168.40.46", "user":"Development"}),
    #dict(defaults,**{"desc":"Raspberry", "ip":"192.168.40.29", "user":"pi-lar"     }),
]

bootstrap_string   = "b0e1e68c9feb193c415697e665a0d50c3ece05b051f9f00aa906caa8f6e3a637:udp4:192.168.30.151:3000"
bootstrap_string_w = "*:udp4:192.168.30.151:3000"

options_progs = [    
      ("node",  "node"),
      ("hydra", "hydra -n 1"),
      ("cloud", "cloud "),
    ]
options_threads = [
      ("single threaded", "-t 0"),
      ("multi threaded", "-t 3"),
    ]
options_jointype = [
      ("hash",     "-j %(bootstrap_string)s"),
      ("wildcard", "-j %(bootstrap_string_w)s"),
    ]
#todo: options_protocol

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
        command_desc = "REGISTER_TEST:%(option_prog_s)s"%locals()        
        command_call = "./{d[bin_dir]}/neuropil_{option_prog} -s 0 -u {d[ip]}".format(**locals())
        for option_thread_s,option_thread in options_threads:
            command_desc2 = command_desc +" %(option_thread_s)s"%locals()
            command_call2 = command_call +" %s"%(option_thread%locals())
            for option_jointype_s,option_jointype in options_jointype:
                command_desc3 = command_desc + " %(option_jointype_s)s"%locals()
                command_call3 = command_call2+" %s"%(option_jointype%locals())
                start_commands += [command_call3]#+" -m "%s""%command_desc3]
 

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
    for i, start_command in enumerate(start_commands):        
        command_str += 'tmux new-window -ad -t neuropil_E2E_tests -n np_{i};'.format(**locals())
        command_str += 'tmux send-keys      -t neuropil_E2E_tests:np_{i} "export LD_LIBRARY_PATH=build/lib:$LD_LIBRARY_PATH";'.format(**locals())
        command_str += 'tmux send-keys      -t neuropil_E2E_tests:np_{i} C-m;'.format(**locals())
        command_str += 'tmux send-keys      -t neuropil_E2E_tests:np_{i} "{start_command}";'.format(**locals())
        command_str += 'tmux send-keys      -t neuropil_E2E_tests:np_{i} C-m;'.format(**locals())
        command_str += 'echo "started np_{i}";'.format(**locals())
    
    command_str = command_str.replace('"','\\"')
    cmd = "ssh -A {d[user]}@{d[ip]} 'bash -l -c \"{command_str}\"' ".format(**locals())
    print(cmd)
    result = os.system(cmd)
    print("Exec on {d[user]}@{d[ip]} = {result}".format(**locals()))
    