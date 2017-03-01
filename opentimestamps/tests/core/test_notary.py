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


class Test_EthereumBlockHeaderAttestation(unittest.TestCase):
    def test_serialize(self):
        attestation = EthereumBlockHeaderAttestation(0)
        expected_serialized = bytes.fromhex('30fe8087b5c7ead7' + '0100')

        ctx = BytesSerializationContext()
        attestation.serialize(ctx)
        self.assertEqual(ctx.getbytes(), expected_serialized)

        ctx = BytesDeserializationContext(expected_serialized)
        attestation2 = TimeAttestation.deserialize(ctx)

        self.assertEqual(attestation2.height, 0)

    def test_verify(self):
        eth_block_1 = {'uncles': [], 'size': 537, 'hash': '0x88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6', 'gasLimit': 5000, 'number': 1, 'totalDifficulty': 34351349760, 'stateRoot': '0xd67e4d450343046425ae4271474353857ab860dbc0a1dde64b41b5cd3a532bf3', 'extraData': '0x476574682f76312e302e302f6c696e75782f676f312e342e32', 'sha3Uncles': '0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347', 'mixHash': '0x969b900de27b6ac6a67742365dd65f55a0526c41fd18e1b16f1a1215c2e66f59', 'transactionsRoot': '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421', 'sealFields': ['0x969b900de27b6ac6a67742365dd65f55a0526c41fd18e1b16f1a1215c2e66f59', '0x539bd4979fef1ec4'], 'transactions': [], 'parentHash': '0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3', 'logsBloom': '0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'author': '0x05a56e2d52c817161883f50c441c3228cfe54d9f', 'gasUsed': 0, 'timestamp': 1438269988, 'nonce': '0x539bd4979fef1ec4', 'difficulty': 17171480576, 'receiptsRoot': '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421', 'miner': '0x05a56e2d52c817161883f50c441c3228cfe54d9f'}
        attestation = EthereumBlockHeaderAttestation(1)
        timestamp = attestation.verify_against_blockheader(bytes.fromhex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"), eth_block_1)
        self.assertEqual(1438269988, timestamp)
