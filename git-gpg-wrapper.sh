#!/bin/sh

# Wrapper for the git-gpg-wrapper
#
# Required because git's gpg.program option doesn't allow you to set command
# line options; see the doc/git-integration.md

echo `dirname $0`/git-gpg-wrapper -- $@
