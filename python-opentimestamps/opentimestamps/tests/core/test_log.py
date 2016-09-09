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

import io
import unittest

from opentimestamps.core.timestamp import *
from opentimestamps.core.log import *
from opentimestamps.core.op import *
from opentimestamps.core.notary import *

class Test_TimestampLogWriter(unittest.TestCase):
    def test_create(self):
        """Create new timestamp log"""
        with io.BytesIO(b'') as fd:
            writer = TimestampLogWriter.create(fd, OpSHA256())

            del writer
            self.assertEqual(fd.getvalue(),
                             b'\x00OpenTimestamps\x00\x00Log\x00\xd9\x19\xc5\x3a\x99\xb1\x12\xe9\xa6\xa1\x00' + # header
                             b'\x08') # sha256 op

    def test_open(self):
        """Open existing timestamp log for writing"""
        serialized = (b'\x00OpenTimestamps\x00\x00Log\x00\xd9\x19\xc5\x3a\x99\xb1\x12\xe9\xa6\xa1\x00' + # header
                      b'\x08') # sha256 op
        with io.BytesIO(serialized) as fd:
            writer = TimestampLogWriter.open(fd)

            self.assertEqual(writer.file_hash_op, OpSHA256())

    def test_append(self):
        """Append timestamps to the log"""
        with io.BytesIO() as fd:
            writer = TimestampLogWriter.create(fd, OpSHA256())

            stamp = Timestamp(OpSHA256()(b''))
            stamp.attestations.add(PendingAttestation('foobar'))
            writer.append(0, stamp)

            del writer

            self.assertEqual(fd.getvalue(),
                             b'\x00OpenTimestamps\x00\x00Log\x00\xd9\x19\xc5\x3a\x99\xb1\x12\xe9\xa6\xa1\x00' + # header
                             b'\x08' + # sha256 op
                             b'\x32' + # start of first packet
                                 b'\x00' + # length
                                 bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') + # sha256 of b'' +
                                 b'\x00' + bytes.fromhex('83dfe30d2ef90c8e' + '07' + '06') + b'foobar' + # attestation
                             b'\x00') # end of packet
