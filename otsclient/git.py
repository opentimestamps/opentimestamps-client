# Copyright (C) 2016 The OpenTimestamps developers
#
# This file is part of the OpenTimestamps Client.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of the OpenTimestamps Client including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import base64
import logging
import sys

from opentimestamps.core.timestamp import Timestamp
from opentimestamps.core.op import OpAppend, OpSHA256
from opentimestamps.core.serialize import BytesSerializationContext, BytesDeserializationContext

# FIXME: This code should be added to python-opentimestamps, although it needs
# some more refactoring to be ready for that.

ASCII_ARMOR_HEADER = b'-----BEGIN OPENTIMESTAMPS GIT TIMESTAMP-----\n\n'
ASCII_ARMOR_FOOTER = b'-----END OPENTIMESTAMPS GIT TIMESTAMP-----\n'

def hash_signed_commit(git_commit, gpg_sig):
    return OpSHA256()(OpSHA256()(git_commit) + OpSHA256()(gpg_sig))

def write_ascii_armored(timestamp, fd, minor_version):
    ctx = BytesSerializationContext()
    timestamp.serialize(ctx)
    serialized_timestamp = ctx.getbytes()

    fd.write(ASCII_ARMOR_HEADER)

    header = (b'\x01' + # major
              bytes([minor_version]))
    b64_encoded = base64.standard_b64encode(header + serialized_timestamp)
    for chunk in (b64_encoded[i:i+64] for i in range(0, len(b64_encoded), 64)):
        fd.write(chunk)
        fd.write(b'\n')

    fd.write(ASCII_ARMOR_FOOTER)

def deserialize_ascii_armored_timestamp(git_commit, gpg_sig):
    stamp_start = gpg_sig.find(ASCII_ARMOR_HEADER)
    if stamp_start == -1:
        return (None, None, None)

    stamp_end = gpg_sig.find(b'\n' + ASCII_ARMOR_FOOTER)
    if stamp_end == -1:
        return (None, None, None)

    base64_encoded_stamp = gpg_sig[stamp_start + len(ASCII_ARMOR_HEADER):stamp_end]

    initial_msg = hash_signed_commit(git_commit, gpg_sig[0:stamp_start])
    try:
        serialized_stamp = base64.standard_b64decode(base64_encoded_stamp)

        major_version = serialized_stamp[0]
        minor_version = serialized_stamp[1]

        if major_version != 1:
            logging.error("Can't verify timestamp; major version %d not known" % major_version)
            sys.exit(1)

        logging.debug("Git timestamp is version %d.%d" % (major_version, minor_version))

        ctx = BytesDeserializationContext(serialized_stamp[2:])
        timestamp = Timestamp.deserialize(ctx, initial_msg)

        return (major_version, minor_version, timestamp)
    except Exception as err:
        logging.error("Bad timestamp: %r" % err)
        return (None, None, None)

def extract_sig_from_git_commit(signed_git_commit):
    """Extract signature (if any) from a signed git commit

    Returns (unsigned_git_commit, gpg_sig)
    """
    unsigned_git_commit = []
    gpg_sig = []

    found_sig = False
    sig_done = False
    for l in signed_git_commit.split(b'\n'):
        if found_sig and sig_done:
            unsigned_git_commit.append(l)

        elif found_sig and not sig_done:
            if l:
                gpg_sig.append(l[1:])
            else:
                unsigned_git_commit.append(l)
                sig_done = True

        elif l.startswith(b'gpgsig '):
            found_sig = True
            gpg_sig.append(l[len(b'gpgsig '):])

        else:
            unsigned_git_commit.append(l)

    return (b'\n'.join(unsigned_git_commit), b'\n'.join(gpg_sig) + b'\n')
