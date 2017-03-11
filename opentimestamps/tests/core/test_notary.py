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

from opentimestamps.core.serialize import *
from opentimestamps.core.notary import *

class Test_UnknownAttestation(unittest.TestCase):
    def test_repr(self):
        """repr(UnknownAttestation)"""
        a = UnknownAttestation(bytes.fromhex('0102030405060708'), b'Hello World!')
        self.assertEqual(repr(a), "UnknownAttestation(b'\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08', b'Hello World!')")

    def test_serialization(self):
        """"Serialization/deserialization of unknown attestations"""
        expected_serialized = bytes.fromhex('0102030405060708') + b'\x0c' + b'Hello World!'
        ctx = BytesDeserializationContext(expected_serialized)
        a = TimeAttestation.deserialize(ctx)

        self.assertEqual(a.TAG, bytes.fromhex('0102030405060708'))
        self.assertEqual(a.payload, b'Hello World!')

        # Test round trip
        ctx = BytesSerializationContext()
        a.serialize(ctx)
        self.assertEqual(expected_serialized, ctx.getbytes())

    def test_deserialize_too_long(self):
        """Deserialization of attestations with oversized payloads"""
        ctx = BytesDeserializationContext(bytes.fromhex('0102030405060708') + b'\x81\x40' + b'x'*8193)
        with self.assertRaises(DeserializationError):
            TimeAttestation.deserialize(ctx)

        # pending attestation
        ctx = BytesDeserializationContext(bytes.fromhex('83dfe30d2ef90c8e') + b'\x81\x40' + b'x'*8193)
        with self.assertRaises(DeserializationError):
            TimeAttestation.deserialize(ctx)

class Test_PendingAttestation(unittest.TestCase):
    def test_serialize(self):
        pending_attestation = PendingAttestation('foobar')
        expected_serialized = bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar'

        ctx = BytesSerializationContext()
        pending_attestation.serialize(ctx)
        self.assertEqual(ctx.getbytes(), expected_serialized)

        ctx = BytesDeserializationContext(expected_serialized)
        pending_attestation2 = TimeAttestation.deserialize(ctx)

        self.assertEqual(pending_attestation2.uri, 'foobar')

    def test_deserialize(self):
        pending_attestation = PendingAttestation('foobar')

        ctx = BytesSerializationContext()
        pending_attestation.serialize(ctx)

        self.assertEqual(ctx.getbytes(), bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar')

    def test_invalid_uri_deserialization(self):
        # illegal character
        ctx = BytesDeserializationContext(bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'fo%bar')
        with self.assertRaises(DeserializationError):
            TimeAttestation.deserialize(ctx)

        # Too long

        # Exactly 1000 bytes is ok
        ctx = BytesDeserializationContext(bytes.fromhex('83dfe30d2ef90c8e' + 'ea07' + 'e807') + b'x'*1000)
        TimeAttestation.deserialize(ctx)

        # But 1001 isn't
        ctx = BytesDeserializationContext(bytes.fromhex('83dfe30d2ef90c8e' + 'eb07' + 'e907') + b'x'*1001)
        with self.assertRaises(DeserializationError):
            TimeAttestation.deserialize(ctx)

    def test_deserialization_trailing_garbage(self):
        ctx = BytesDeserializationContext(bytes.fromhex('83dfe30d2ef90c8e' + '08' + '06') + b'foobarx')
        with self.assertRaises(TrailingGarbageError):
            TimeAttestation.deserialize(ctx)

class Test_BitcoinBlockHeaderAttestation(unittest.TestCase):
    def test_deserialization_trailing_garbage(self):
        ctx = BytesDeserializationContext(bytes.fromhex('0588960d73d71901' +
                                                        '02' + # two bytes of payload
                                                        '00' + # genesis block!
                                                        'ff')) # one byte of trailing garbage
        with self.assertRaises(TrailingGarbageError):
            TimeAttestation.deserialize(ctx)
