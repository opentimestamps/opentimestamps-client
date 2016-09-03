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

import unittest

from opentimestamps.core.notary import *
from opentimestamps.core.serialize import *
from opentimestamps.core.timestamp import *
from opentimestamps.core.op import *

class Test_Timestamp(unittest.TestCase):
    def test_add_op(self):
        """Adding operations to timestamps"""
        t = Timestamp(b'abcd')
        t.ops.add(OpReverse())
        self.assertEqual(t.ops[OpReverse()], Timestamp(b'dcba'))

        # The second add should succeed
        t.ops.add(OpReverse())
        self.assertEqual(t.ops[OpReverse()], Timestamp(b'dcba'))

    def test_set_result_timestamp(self):
        """Setting an op result timestamp"""
        t1 = Timestamp(b'foo')
        t2 = t1.ops.add(OpAppend(b'bar'))
        t3 = t2.ops.add(OpAppend(b'baz'))

        self.assertEqual(t1.ops[OpAppend(b'bar')].ops[OpAppend(b'baz')].msg, b'foobarbaz')

        t1.ops[OpAppend(b'bar')] = Timestamp(b'foobar')

        self.assertTrue(OpAppend(b'baz') not in t1.ops[OpAppend(b'bar')].ops)

    def test_set_fail_if_wrong_message(self):
        """Setting an op result timestamp fails if the messages don't match"""
        t = Timestamp(b'abcd')
        t.ops.add(OpReverse())

        with self.assertRaises(ValueError):
            t.ops[OpReverse()] = Timestamp(b'wrong')

    def test_merge(self):
        """Merging timestamps"""
        with self.assertRaises(ValueError):
            Timestamp(b'a').merge(Timestamp(b'b'))

        t1 = Timestamp(b'a')
        t2 = Timestamp(b'a')
        t2.attestations.add(PendingAttestation(b'foobar'))

        t1.merge(t2)
        self.assertEqual(t1, t2)

        # FIXME: more tests

    def test_serialization(self):
        """Timestamp serialization/deserialization"""
        def T(expected_instance, expected_serialized):
            ctx = BytesSerializationContext()
            expected_instance.serialize(ctx)
            actual_serialized = ctx.getbytes()

            self.assertEqual(expected_serialized, actual_serialized)

            actual_instance = Timestamp.deserialize(BytesDeserializationContext(expected_serialized), expected_instance.msg)
            self.assertEqual(expected_instance, actual_instance)


        stamp = Timestamp(b'foo')
        stamp.attestations.add(PendingAttestation(b'foobar'))

        T(stamp, b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar')

        stamp.attestations.add(PendingAttestation(b'barfoo'))
        T(stamp, b'\xff' + (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'barfoo') + \
                 (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar'))


        stamp.attestations.add(PendingAttestation(b'foobaz'))
        T(stamp, b'\xff' + (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'barfoo') + \
                 b'\xff' + (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar') + \
                 (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobaz'))

        sha256_stamp = stamp.ops.add(OpSHA256())

        # Should fail - empty timestamps can't be serialized
        with self.assertRaises(ValueError):
            ctx = BytesSerializationContext()
            stamp.serialize(ctx)

        sha256_stamp.attestations.add(PendingAttestation(b'deeper'))
        T(stamp, b'\xff' + (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'barfoo') + \
                 b'\xff' + (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar') + \
                 b'\xff' + (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobaz') + \
                 b'\x08' + (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'deeper'))

class Test_DetachedTimestampFile(unittest.TestCase):
    def test_create_from_file(self):
        file_stamp = DetachedTimestampFile.from_fd(OpSHA256(), io.BytesIO(b''))
        self.assertEqual(file_stamp.file_digest, bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'))

    def test_hash_fd(self):
        file_stamp = DetachedTimestampFile.from_fd(OpSHA256(), io.BytesIO(b''))

        result = file_stamp.file_hash_op.hash_fd(io.BytesIO(b''))
        self.assertEqual(result, bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'))

    def test_serialization(self):
        def T(expected_instance, expected_serialized):
            ctx = BytesSerializationContext()
            expected_instance.serialize(ctx)
            actual_serialized = ctx.getbytes()

            self.assertEqual(expected_serialized, actual_serialized)

            actual_instance = DetachedTimestampFile.deserialize(BytesDeserializationContext(expected_serialized))
            self.assertEqual(expected_instance, actual_instance)

        file_stamp = DetachedTimestampFile.from_fd(OpSHA256(), io.BytesIO(b''))
        file_stamp.timestamp.attestations.add(PendingAttestation(b'foobar'))

        T(file_stamp, (b'\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94\x00' +
                       b'\x20' + bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') +
                       b'\x08' +
                       b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar'))
