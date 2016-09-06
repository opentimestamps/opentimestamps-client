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
        ctx = BytesDeserializationContext(bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'fo%obar')
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
