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
        t.ops.add(OpAppend(b'efgh'))
        self.assertEqual(t.ops[OpAppend(b'efgh')], Timestamp(b'abcdefgh'))

        # The second add should succeed with the timestamp unchanged
        t.ops.add(OpAppend(b'efgh'))
        self.assertEqual(t.ops[OpAppend(b'efgh')], Timestamp(b'abcdefgh'))

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
        t.ops.add(OpSHA256())

        with self.assertRaises(ValueError):
            t.ops[OpSHA256()] = Timestamp(b'wrong')

    def test_merge(self):
        """Merging timestamps"""
        with self.assertRaises(ValueError):
            Timestamp(b'a').merge(Timestamp(b'b'))

        t1 = Timestamp(b'a')
        t2 = Timestamp(b'a')
        t2.attestations.add(PendingAttestation('foobar'))

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
        stamp.attestations.add(PendingAttestation('foobar'))

        T(stamp, b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar')

        stamp.attestations.add(PendingAttestation('barfoo'))
        T(stamp, b'\xff' + (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'barfoo') + \
                 (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar'))


        stamp.attestations.add(PendingAttestation('foobaz'))
        T(stamp, b'\xff' + (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'barfoo') + \
                 b'\xff' + (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar') + \
                 (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobaz'))

        sha256_stamp = stamp.ops.add(OpSHA256())

        # Should fail - empty timestamps can't be serialized
        with self.assertRaises(ValueError):
            ctx = BytesSerializationContext()
            stamp.serialize(ctx)

        sha256_stamp.attestations.add(PendingAttestation('deeper'))
        T(stamp, b'\xff' + (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'barfoo') + \
                 b'\xff' + (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar') + \
                 b'\xff' + (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobaz') + \
                 b'\x08' + (b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'deeper'))

    def test_deserialization_invalid_op_msg(self):
        """Timestamp deserialization when message is invalid for op"""
        serialized = (b'\xf0\x01\x00' + # OpAppend(b'\x00')
                      b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'barfoo') # perfectly valid pending attestation

        # Perfectly ok, results is 4096 bytes long
        Timestamp.deserialize(BytesDeserializationContext(serialized), b'.'*4095)

        with self.assertRaises(DeserializationError):
            # Not ok, result would be 4097 bytes long
            Timestamp.deserialize(BytesDeserializationContext(serialized), b'.'*4096)

    def test_deserialization_invalid_op_msg_2(self):
        """Deserialization of a timestamp that exceeds the recursion limit"""
        serialized = (b'\x08'*256 + # OpSHA256, 256 times
                      b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'barfoo') # perfectly valid pending attestation

        with self.assertRaises(RecursionLimitError):
            Timestamp.deserialize(BytesDeserializationContext(serialized), b'')

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
        file_stamp.timestamp.attestations.add(PendingAttestation('foobar'))

        T(file_stamp, (b'\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94' +
                       b'\x01' + # major version
                       b'\x08' + bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') +
                       b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar'))

    def test_deserialization_failures(self):
        """Deserialization failures"""

        for serialized, expected_error in ((b'', BadMagicError),
                                           (b'\x00Not a OpenTimestamps Proof \x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94\x01', BadMagicError),
                                           (b'\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94\x00', UnsupportedMajorVersion),
                                           (b'\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94\x01' +
                                            b'\x42' + # Not a valid opcode
                                            b'\x00'*32 +
                                            b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar', DeserializationError),
                                           (b'\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94\x01' +
                                             b'\x08' + bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') +
                                             b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar' +
                                             b'trailing garbage', TrailingGarbageError)):

            with self.assertRaises(expected_error):
                ctx = BytesDeserializationContext(serialized)
                DetachedTimestampFile.deserialize(ctx)


class Test_cat_sha256(unittest.TestCase):
    def test(self):
        left = Timestamp(b'foo')
        right = Timestamp(b'bar')

        stamp_left_right= cat_sha256(left, right)
        self.assertEqual(stamp_left_right.msg, bytes.fromhex('c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2'))

        righter = Timestamp(b'baz')
        stamp_righter = cat_sha256(stamp_left_right, righter)
        self.assertEqual(stamp_righter.msg, bytes.fromhex('23388b16c66f1fa37ef14af8eb081712d570813e2afb8c8ae86efa726f3b7276'))


class Test_make_merkle_tree(unittest.TestCase):
    def test(self):
        def T(n, expected_merkle_root):
            roots = [Timestamp(bytes([i])) for i in range(n)]
            tip = make_merkle_tree(roots)

            self.assertEqual(tip.msg, expected_merkle_root)

            for root in roots:
                pass # FIXME: check all roots lead to same timestamp

        # Returned unchanged!
        T(1, bytes.fromhex('00'))

        # Manually calculated w/ pen-and-paper
        T(2, bytes.fromhex('b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2'))
        T(3, bytes.fromhex('e6aa639123d8aac95d13d365ec3779dade4b49c083a8fed97d7bfc0d89bb6a5e'))
        T(4, bytes.fromhex('7699a4fdd6b8b6908a344f73b8f05c8e1400f7253f544602c442ff5c65504b24'))
        T(5, bytes.fromhex('aaa9609d0c949fee22c1c941a4432f32dc1c2de939e4af25207f0dc62df0dbd8'))
        T(6, bytes.fromhex('ebdb4245f648b7e77b60f4f8a99a6d0529d1d372f98f35478b3284f16da93c06'))
        T(7, bytes.fromhex('ba4603a311279dea32e8958bfb660c86237157bf79e6bfee857803e811d91b8f'))
