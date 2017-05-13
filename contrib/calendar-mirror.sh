#!/bin/bash

# The three official OpenTimestamps calendars currently in operation make their
# raw journal and calendar databases available for backup as a temporary
# measure while we work on a better, formally defined, mirroring scheme.
#
# The best way to use this script is with a git repository: create an empty git
# repo, and then call this script with that repo as the argument. Since the
# calendar database information is mostly read-only, git's compression acts as
# a very effective incremental backup. Secondly, the -N argument to wget
# ensures that files that haven't been modified aren't re-downloaded
# unnecessarily.
#
# If you have a better way of doing this, pull-reqs are much appreciated! The
# author of this script is a Bitcoin expert, not an HTTP protocol expert. :)

cd $1

(wget --no-parent -Nr https://alice.btc.calendar.opentimestamps.org/calendar/ ;
 wget --no-parent -Nr https://bob.btc.calendar.opentimestamps.org/calendar/ ;
 wget --no-parent -Nr https://finney.calendar.eternitywall.com/calendar/ ) 2> log

git add -A
git commit -m 'backup'
