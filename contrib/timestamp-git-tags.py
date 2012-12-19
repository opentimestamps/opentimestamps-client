#!/usr/bin/python3

import sys
from subprocess import call,Popen,PIPE

if len(sys.argv) < 2:
    print('Usage: timestamp-git-tags.py path-to-ots [ots options]')
    sys.exit(1)

with Popen('git show-ref --tags', shell=True, stdout=PIPE) as git:
    for l in git.stdout.readlines():
        l = str(l,'utf8')
        (ref,tag) = l.strip().split(' ')

        tag = tag.split('/', 2)[2]

        call(sys.argv[1:] + ['-d', ref, tag + '.ots'])
