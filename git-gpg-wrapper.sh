#!/bin/sh

# Wrapper for the git-gpg-wrapper
#
# Required because git's gpg.program option doesn't allow you to set command
# line options; see the doc/git-integration.md

`dirname $0`/git-gpg-wrapper --gpg-program `which gpg` -- $@
