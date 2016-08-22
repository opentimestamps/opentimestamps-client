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

from opentimestamps.core.op import Op, OpAppend, OpPrepend, OpSHA256, OpRIPEMD160

def cat_then_unary_op(op, left, right):
    """Concatenate left and right ops, then perform a unary operation on them

    Appropriate intermediary append/prepend operations will be created as
    needed for left and right
    """

    left_append_op = OpAppend(left, right)
    if isinstance(left, Op):
        left.next_op = left_append_op
    right_prepend_op = OpPrepend(left, right)
    if isinstance(right, Op):
        right.next_op = right_prepend_op

    assert left_append_op.result == right_prepend_op.result

    unary_op = op(left_append_op)

    left_append_op.next_op = unary_op
    right_prepend_op.next_op = unary_op

    return unary_op

def cat_sha256(left, right):
    return cat_then_unary_op(OpSHA256, left, right)

def cat_sha256d(left, right):
    sha256_op1 = cat_sha256(left, right)
    sha256_op2 = OpSHA256(sha256_op1)
    sha256_op1.next_op = sha256_op2
    return sha256_op2

def make_merkle_tree(ops, binop=cat_sha256):
    """Make a merkle tree from an iterable of operations

    Function binop(left, right) is used to contactenate and then hash each
    digest.

    Returns the operation at the tip of the tree
    """

    while True:
        ops = iter(ops)

        try:
            prev_op = next(ops)
        except StopIteration:
            raise ValueError("Need at least one operation")

        next_ops = []
        for op in ops:
            if prev_op is not None:
                next_ops.append(cat_sha256(prev_op, op))
                prev_op = None
            else:
                prev_op = op

        if not next_ops:
            return prev_op

        if prev_op is not None:
            next_ops.append(prev_op)

        ops = next_ops
