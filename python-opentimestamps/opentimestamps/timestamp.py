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

"""Convenience functions for dealing with operations"""

import os

from opentimestamps.core.op import Op, OpAppend, OpPrepend, OpSHA256, OpRIPEMD160
from opentimestamps.core.timestamp import Timestamp


def cat_then_unary_op(unary_op_cls, left, right):
    """Concatenate left and right, then perform a unary operation on them

    left and right can be either timestamps or bytes.

    Appropriate intermediary append/prepend operations will be created as
    needed for left and right.
    """
    if not isinstance(left, Timestamp):
        left = Timestamp(left)

    if not isinstance(right, Timestamp):
        right = Timestamp(right)

    left_append_stamp = left.ops.add(OpAppend(right.msg))
    right_prepend_stamp = right.ops.add(OpPrepend(left.msg))

    # Left and right should produce the same thing, so we can set the timestamp
    # of the left to the right.
    left.ops[OpAppend(right.msg)] = right_prepend_stamp

    return right_prepend_stamp.ops.add(unary_op_cls())


def cat_sha256(left, right):
    return cat_then_unary_op(OpSHA256, left, right)


def cat_sha256d(left, right):
    sha256_timestamp = cat_sha256(left, right)
    return sha256_timestamp.ops.add(OpSHA256())


def make_merkle_tree(timestamps, binop=cat_sha256):
    """Merkelize a set of timestamps

    A merkle tree of all the timestamps is built in-place using binop() to
    timestamp each pair of timestamps.

    Returns the timestamp for the tip of the tree.
    """

    stamps = timestamps
    while True:
        stamps = iter(stamps)

        try:
            prev_stamp = next(stamps)
        except StopIteration:
            raise ValueError("Need at least one timestamp")

        next_stamps = []
        for stamp in stamps:
            if prev_stamp is not None:
                next_stamps.append(cat_sha256(prev_stamp, stamp))
                prev_stamp = None
            else:
                prev_stamp = stamp

        if not next_stamps:
            return prev_stamp

        if prev_stamp is not None:
            next_stamps.append(prev_stamp)

        stamps = next_stamps


def nonce_timestamp(private_timestamp):
    """Create a nonced version of a timestamp for privacy"""
    stamp2 = private_timestamp.ops.add(OpAppend(os.urandom(16)))
    return stamp2.ops.add(OpSHA256())
