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

class Test_Op(unittest.TestCase):
    def test_append(self):
        op = OpAppend(b'msg', b'suffix')
        self.assertEqual(op.timestamp.msg, b'msgsuffix')

    def test_prepend(self):
        op = OpPrepend(b'msg', b'prefix')
        self.assertEqual(op.timestamp.msg, b'prefixmsg')

    def test_reverse(self):
        op = OpReverse(b'abcd')
        self.assertEqual(op.timestamp.msg, b'dcba')

    def test_sha256(self):
        op = OpSHA256(b'')
        self.assertEqual(op.timestamp.msg, bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'))

    def test_ripemd160(self):
        op = OpRIPEMD160(b'')
        self.assertEqual(op.timestamp.msg, bytes.fromhex('9c1185a5c5e9fc54612808977ee8f548b2258d31'))

    def test_changing_timestamps(self):
        op1 = OpRIPEMD160(b'')
        op2 = OpRIPEMD160(b'')

        self.assertIsNot(op1.timestamp, op2.timestamp)

        op1.timestamp = op2.timestamp
        self.assertIs(op1.timestamp, op2.timestamp)

        with self.assertRaises(ValueError):
            op1.timestamp = Timestamp(b'')

    def test_equality(self):
        self.assertEqual(OpRIPEMD160(b''), OpRIPEMD160(b''))
        self.assertEqual(OpReverse(b''), OpReverse(b''))

        self.assertNotEqual(OpRIPEMD160(b''), OpSHA256(b''))

        # Not equal even if results are same
        self.assertNotEqual(OpAppend(b'', b''), OpPrepend(b'', b''))

        # Not equal if timestamps differ
        op1 = OpSHA256(b'')
        op2 = OpSHA256(b'')
        op2.timestamp.add_op(OpSHA256)
        self.assertNotEqual(op1, op2)

        # Equal if timestamps same
        op1.timestamp.add_op(OpSHA256)
        self.assertEqual(op1, op2)

    def test_result(self):
        op = OpSHA256(b'')
        self.assertEqual(op.result, op.timestamp.msg)


class Test_Timestamp(unittest.TestCase):
    def test_merge(self):
        with self.assertRaises(ValueError):
            Timestamp(b'a').merge(Timestamp(b'b'))

        t1 = Timestamp(b'a')
        t2 = Timestamp(b'a')
        t2.add_op(OpVerify, PendingAttestation(b'foobar'))

        t1.merge(t2)
        self.assertEqual(t1.ops, t2.ops)

    def test_serialization(self):
        def T(expected_instance, expected_serialized):
            ctx = BytesSerializationContext()
            expected_instance.serialize(ctx)
            actual_serialized = ctx.getbytes()

            self.assertEqual(expected_serialized, actual_serialized)

            actual_instance = Timestamp.deserialize(BytesDeserializationContext(expected_serialized), expected_instance.msg)
            self.assertEqual(expected_instance, actual_instance)


        stamp = Timestamp(b'foo')
        stamp.add_op(OpVerify, PendingAttestation(b'foobar'))

        T(stamp, b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar')

        stamp.add_op(OpVerify, PendingAttestation(b'foobar'))
        T(stamp, b'\xff' + (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar') + \
                 (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar'))


        stamp.add_op(OpVerify, PendingAttestation(b'foobar'))
        T(stamp, b'\xff' + (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar') + \
                 b'\xff' + (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar') + \
                 (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar'))

        sha256_op = stamp.add_op(OpSHA256)

        # Shoudl fail - empty timestamps can't be serialized
        with self.assertRaises(ValueError):
            ctx = BytesSerializationContext()
            stamp.serialize(ctx)

        sha256_op.timestamp.add_op(OpVerify, PendingAttestation(b'deeper'))
        T(stamp, b'\xff' + (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar') + \
                 b'\xff' + (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar') + \
                 b'\xff' + (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar') + \
                 b'\x08' + (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'deeper'))

class Test_DetachedTimestampFile(unittest.TestCase):
    def test_create_from_file(self):
        file_stamp = DetachedTimestampFile.from_fd(OpSHA256, io.BytesIO(b''))
        self.assertEqual(file_stamp.file_digest, bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'))

    def test_hash_fd(self):
        file_stamp = DetachedTimestampFile.from_fd(OpSHA256, io.BytesIO(b''))

        op2 = file_stamp.hash_fd(io.BytesIO(b''))
        self.assertEqual(file_stamp.timestamp_op, op2)

    def test_serialization(self):
        def T(expected_instance, expected_serialized):
            ctx = BytesSerializationContext()
            expected_instance.serialize(ctx)
            actual_serialized = ctx.getbytes()

            self.assertEqual(expected_serialized, actual_serialized)

            actual_instance = DetachedTimestampFile.deserialize(BytesDeserializationContext(expected_serialized))
            self.assertEqual(expected_instance, actual_instance)

        file_stamp = DetachedTimestampFile.from_fd(OpSHA256, io.BytesIO(b''))
        file_stamp.timestamp_op.timestamp.add_op(OpVerify, PendingAttestation(b'foobar'))

        T(file_stamp, (b'\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94\x00' +
                       b'\x20' + bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') +
                       b'\x08' +
                       b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar'))
