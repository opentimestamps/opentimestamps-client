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
# Debug the OpenTimeStamps process for one call:
#
# > OPENTIMESTAMPS_GIT_GPG_WRAPPER_DEBUG=true OPENTIMESTAMPS_GIT_GPG_WRAPPER_FLAGS='-vvvvv' git log --show-signature
#
# Always debug the OpenTimeStamps process:
#
# > git config --global opentimestamps.debug true
# > git config --global opentimestamps.flags -vvvvvvv
#
# Don't attempt to connect to a local Bitcoin node (e.g. for verification).
#
# > git config --global opentimestamps.flags '--no-bitcoin'

# defaults
test -n "$GPG" || GPG=gpg
test -n "$OPENTIMESTAMPS_GIT_GPG_WRAPPER_DEBUG" || OPENTIMESTAMPS_GIT_GPG_WRAPPER_DEBUG="`git config opentimestamps.debug 2>/dev/null || true`"
test -n "$OPENTIMESTAMPS_GIT_GPG_WRAPPER"       || OPENTIMESTAMPS_GIT_GPG_WRAPPER=ots-git-gpg-wrapper
test -n "$OPENTIMESTAMPS_GIT_GPG_WRAPPER_FLAGS" || OPENTIMESTAMPS_GIT_GPG_WRAPPER_FLAGS="`git config opentimestamps.flags 2>/dev/null || true`"

function debug() { if is_true "$OPENTIMESTAMPS_GIT_GPG_WRAPPER_DEBUG";then echo >&2 "ots: $@";fi }

# config value pattern matching
true_pattern='^(y(es)?|true|enable)$'
false_pattern='^(no?|false|disable)$'
function check_pattern() { echo "$1" | grep -Eiq "$2"; }
function is_true() { if check_pattern "$1" "$false_pattern";then return 1;fi;check_pattern "$1" "$true_pattern"; }
# This git subcommand-detection fails if there are direct arguments to `git` before the subcommand.
# The full git cmdline should be parsed properly. Instead, we skip the git subcommand check in this case.
git_command="`cat /proc/"$PPID"/cmdline | tr '\0' '\n' | tail -n+2 | head -n1`"
if (echo "$git_command" | grep -qvx '[a-z]\+');then
    debug "Can't determine git command if there are direct options to git, sorry..."
    git_command=
fi
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
    git_config_opentimestamps_only_for="`git config opentimestamps.only-for 2>/dev/null`"
    if test -n "$git_config_opentimestamps_only_for" -a -n "$git_command";then
        if (echo "$git_config_opentimestamps_only_for" | grep -o '[a-z]\+' | grep -qFx "$git_command" >/dev/null 2>/dev/null);then
            debug "Enabling OpenTimestamps as \`git config opentimestamps.only-for\` = '$git_config_opentimestamps_only_for' contains the current git command '$git_command'"
        else
            debug "Disabling OpenTimestamps as \`git config opentimestamps.only-for\` = '$git_config_opentimestamps_only_for' doesn't contain the current git command '$git_command'"
            return 1
        fi
    fi
    git_config_opentimestamps_enable="`git config opentimestamps.enable 2>/dev/null`"
    if test -n "$git_config_opentimestamps_enable";then
        if is_true "$git_config_opentimestamps_enable";then
            debug "Enabling OpenTimestamps due to \`git config opentimestamps.enable\` = '$git_config_opentimestamps_enable'"
            return 0
        else
            debug "Disabling OpenTimestamps due to \`git config opentimestamps.enable\` = '$git_config_opentimestamps_enable'"
            return 1
        fi
    fi
    debug "Enabling OpenTimestamps"
    return 0
}

if opentimestamps_enabled;then
    debug "executing >>>$OPENTIMESTAMPS_GIT_GPG_WRAPPER $OPENTIMESTAMPS_GIT_GPG_WRAPPER_FLAGS -- $@<<<"
    exec $OPENTIMESTAMPS_GIT_GPG_WRAPPER $OPENTIMESTAMPS_GIT_GPG_WRAPPER_FLAGS -- "$@"
else
    debug "executing >>>$GPG $@<<<"
    exec $GPG "$@"
fi
