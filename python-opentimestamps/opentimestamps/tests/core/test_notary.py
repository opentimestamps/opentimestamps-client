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

class Test_Attestation(unittest.TestCase):
    def test_serialize(self):
        pending_attestation = PendingAttestation(b'foobar')
        expected_serialized = bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar'

        ctx = BytesSerializationContext()
        pending_attestation.serialize(ctx)
        self.assertEqual(ctx.getbytes(), expected_serialized)

        ctx = BytesDeserializationContext(expected_serialized)
        pending_attestation2 = TimeAttestation.deserialize(ctx)

        self.assertEqual(pending_attestation2.uri, b'foobar')

    def test_deserialize(self):
        pending_attestation = PendingAttestation(b'foobar')

        ctx = BytesSerializationContext()
        pending_attestation.serialize(ctx)

        self.assertEqual(ctx.getbytes(), bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar')
