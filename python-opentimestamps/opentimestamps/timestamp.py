# Copyright (C) 2016 The OpenTimestamps developers
#
# This file is part of python-opentimestamps.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-opentimestamps including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

"""Convenience functions for creating timestamps"""

import os

from opentimestamps.core.op import OpAppend, OpSHA256

def nonce_timestamp(private_timestamp, crypt_op=OpSHA256(), length=16):
    """Create a nonced version of a timestamp for privacy"""
    stamp2 = private_timestamp.ops.add(OpAppend(os.urandom(length)))
    return stamp2.ops.add(crypt_op)
