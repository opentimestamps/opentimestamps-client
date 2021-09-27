#!/bin/sh

# Wrapper for the ots-git-gpg-wrapper
#
# Required because git's gpg.program option doesn't allow you to set command
# line options; see the doc/git-integration.md

##############################
### Configuration Examples ###
##############################

# Disable OpenTimestamps for the current repository:
# 
# > git config opentimestamps.enable false
# 
# Disable OpenTimestamps by default for all git repositories on this machine:
# 
# > git config --global opentimestamps.enable false
#
# Temporarily (re)enable OpenTimestamps signatures in `git log`:
#
# > OPENTIMESTAMPS=true git log --show-signature
# 
# Temporarily ignore OpenTimestamps signatures in `git log`:
#
# > OPENTIMESTAMPS=false git log --show-signature
# 
# Don't use OpenTimestamps for timestamping for one commit:
#
# > OPENTIMESTAMPS=false git commit -m "commit message"
# 
# Debug the OpenTimeStamps process:
#
# > OPENTIMESTAMPS_GIT_GPG_WRAPPER_DEBUG=true OPENTIMESTAMPS_GIT_GPG_WRAPPER_FLAGS='-vvvvv' git log --show-signature

# defaults
test -n "$GPG" || GPG=gpg
test -n "$OPENTIMESTAMPS_GIT_GPG_WRAPPER_DEBUG" || OPENTIMESTAMPS_GIT_GPG_WRAPPER_DEBUG=false
test -n "$OPENTIMESTAMPS_GIT_GPG_WRAPPER" || OPENTIMESTAMPS_GIT_GPG_WRAPPER=ots-git-gpg-wrapper
test -n "$OPENTIMESTAMPS_GIT_GPG_WRAPPER_FLAGS" || OPENTIMESTAMPS_GIT_GPG_WRAPPER_FLAGS=

function debug() { if is_true "$OPENTIMESTAMPS_GIT_GPG_WRAPPER_DEBUG";then echo >&2 "ots: $@";fi }

# config value pattern matching
true_pattern='^(y(es)?|true|enable)$'
false_pattern='^(no?|false|disable)$'
function check_pattern() { echo "$1" | grep -Eiq "$2"; }
function is_true() { if check_pattern "$1" "$false_pattern";then return 1;fi;check_pattern "$1" "$true_pattern"; }
function opentimestamps_enabled() { 
    if test -n "$OPENTIMESTAMPS";then
        if is_true "$OPENTIMESTAMPS";then
            debug "Enabling OpenTimestamps due to OPENTIMESTAMPS='$OPENTIMESTAMPS'"
            return 0
        else
            debug "Disabling OpenTimestamps due to OPENTIMESTAMPS='$OPENTIMESTAMPS'"
            return 1
        fi
    fi
    git_config_opentimestamps_enable="`git config opentimestamps.enable`"
    if test -n "$git_config_opentimestamps_enable";then
        if is_true "$git_config_opentimestamps_enable";then
            debug "Enabling OpenTimestamps due to \`git config opentimestamps.enable\` = '$git_config_opentimestamps_enable'"
            return 0
        else
            debug "Disabling OpenTimestamps due to \`git config opentimestamps.enable\` = '$git_config_opentimestamps_enable'"
            return 1
        fi
    fi
    debug "Enabling OpenTimestamps as both \`git config opentimestamps.enable\` and OPENTIMESTAMPS are unset"
    return 0
}

if opentimestamps_enabled;then
    debug "executing >>>$OPENTIMESTAMPS_GIT_GPG_WRAPPER $OPENTIMESTAMPS_GIT_GPG_WRAPPER_FLAGS -- $@<<<"
    exec $OPENTIMESTAMPS_GIT_GPG_WRAPPER $OPENTIMESTAMPS_GIT_GPG_WRAPPER_FLAGS -- "$@"
else
    debug "executing >>>$GPG $@<<<"
    exec $GPG "$@"
fi
