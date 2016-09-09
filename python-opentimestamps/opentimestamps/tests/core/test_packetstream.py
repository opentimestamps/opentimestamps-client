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

import contextlib
import io
import os
import tempfile
import unittest

from opentimestamps.core.packetstream import *

class Test_PacketWriter(unittest.TestCase):
    def test_open_close(self):
        """Open followed by close writes a packet"""
        with tempfile.NamedTemporaryFile() as tmpfile:
            with open(tmpfile.name, 'wb') as fd:
                writer = PacketWriter(fd)
                self.assertFalse(writer.closed)
                writer.close()
                self.assertTrue(writer.closed)

            with open(tmpfile.name, 'rb') as fd:
                self.assertEqual(fd.read(), b'\x00')

    def test_with(self):
        """Using PacketWrite as a context manager"""
        with tempfile.NamedTemporaryFile() as tmpfile:
            with open(tmpfile.name, 'wb') as fd:
                with PacketWriter(fd) as writer:
                    pass

            with open(tmpfile.name, 'rb') as fd:
                self.assertEqual(fd.read(), b'\x00')

    @contextlib.contextmanager
    def assert_written(self, expected_contents):
        with tempfile.NamedTemporaryFile() as tmpfile:
            with open(tmpfile.name, 'wb') as fd:
                with PacketWriter(fd) as writer:
                    yield writer

            with open(tmpfile.name, 'rb') as fd:
                actual_contents = fd.read()
                self.assertEqual(expected_contents, actual_contents)

    def test_empty_write(self):
        """Empty writes are no-ops"""
        with self.assert_written(b'\x00') as writer:
            writer.write(b'')
        with self.assert_written(b'\x00') as writer:
            writer.write(b'')
            writer.write(b'')

    def test_sub_block_write(self):
        """Writing less than one sub-block"""
        with self.assert_written(b'\x01a\x00') as writer:
            writer.write(b'a')
        with self.assert_written(b'\x02ab\x00') as writer:
            writer.write(b'a')
            writer.write(b'b')

        with self.assert_written(b'\xff' + b'x'*255 + b'\x00') as writer:
            writer.write(b'x'*254)
            writer.write(b'x'*1)
        with self.assert_written(b'\xff' + b'x'*255 + b'\x00') as writer:
            writer.write(b'x'*255)

    def test_multi_sub_block_writes(self):
        """Writing more than one sub-block"""
        with self.assert_written(b'\xff' + b'x'*255 + b'\x01x' + b'\x00') as writer:
            writer.write(b'x' * 255)
            writer.write(b'x' * 1)
        with self.assert_written(b'\xff' + b'x'*255 + b'\x01x' + b'\x00') as writer:
            writer.write(b'x' * (255 + 1))

        with self.assert_written(b'\xff' + b'x'*255 + b'\xfe' + b'x'*254 + b'\x00') as writer:
            writer.write(b'x' * 255)
            writer.write(b'x' * 254)
        with self.assert_written(b'\xff' + b'x'*255 + b'\xfe' + b'x'*254 + b'\x00') as writer:
            writer.write(b'x' * (255 + 254))

        with self.assert_written(b'\xff' + b'x'*255 + b'\xff' + b'x'*255 + b'\x00') as writer:
            writer.write(b'x' * 255)
            writer.write(b'x' * 255)
        with self.assert_written(b'\xff' + b'x'*255 + b'\xff' + b'x'*255 + b'\x00') as writer:
            writer.write(b'x' * (255 + 255))

        with self.assert_written(b'\xff' + b'x'*255 + b'\xff' + b'x'*255 + b'\x01x' + b'\x00') as writer:
            writer.write(b'x' * 255)
            writer.write(b'x' * 255)
            writer.write(b'x' * 1)
        with self.assert_written(b'\xff' + b'x'*255 + b'\xff' + b'x'*255 + b'\x01x' + b'\x00') as writer:
            writer.write(b'x' * (255 + 255 + 1))

    def test_flush(self):
        with self.assert_written(b'\x05Hello' + b'\x06World!' + b'\x00') as writer:
            writer.write(b'Hello')
            writer.flush()
            writer.write(b'World!')

    def test_del_does_not_close(self):
        """Deleting a PacketWriter does not close the underlying stream"""
        with io.BytesIO() as fd:
            writer = PacketWriter(fd)
            del writer

            self.assertFalse(fd.closed)

class Test_PacketReader(unittest.TestCase):
    def test_close_only_packet(self):
        """Close does not close underlying stream"""
        with io.BytesIO(b'\x00') as fd:
            reader = PacketReader(fd)
            reader.close()

            self.assertTrue(reader.closed)
            self.assertFalse(fd.closed)

    def test_valid_empty_packet(self):
        """Empty, but valid, packets"""
        with io.BytesIO(b'\x00') as fd:
            reader = PacketReader(fd)
            self.assertEqual(fd.tell(), 1)

            self.assertFalse(reader.end_of_packet)

            # reading nothing is a no-op
            self.assertEqual(reader.read(0), b'')
            self.assertFalse(reader.end_of_packet)
            self.assertEqual(fd.tell(), 1)

            self.assertEqual(reader.read(1), b'')
            self.assertTrue(reader.end_of_packet)

            self.assertEqual(fd.tell(), 1)

    def test_single_sub_packet_read(self):
        """Reading less than a single sub-packet"""
        with io.BytesIO(b'\x0cHello World!\x00') as fd:
            reader = PacketReader(fd)
            self.assertEqual(fd.tell(), 1)

            self.assertEqual(reader.read(12), b'Hello World!')
            self.assertFalse(reader.end_of_packet) # reader hasn't found out yet
            self.assertEqual(fd.tell(), 13)

            self.assertEqual(reader.read(), b'')
            self.assertTrue(reader.end_of_packet)

            self.assertEqual(fd.tell(), 14)

    def test_multi_sub_packet_read(self):
        """Reads that span multiple sub-packets"""
        with io.BytesIO(b'\x01H' + b'\x0bello World!' + b'\x00') as fd:
            reader = PacketReader(fd)
            self.assertEqual(fd.tell(), 1)

            self.assertEqual(reader.read(12), b'Hello World!')
            self.assertFalse(reader.end_of_packet) # reader hasn't found out yet
            self.assertEqual(fd.tell(), 14)

            self.assertEqual(reader.read(), b'')
            self.assertTrue(reader.end_of_packet)

            self.assertEqual(fd.tell(), 15)

    def test_missing_packet(self):
        """Completely missing packet raises PacketMissingError"""
        with io.BytesIO(b'') as fd:
            with self.assertRaises(PacketMissingError):
                PacketReader(fd)

    def test_truncated_packet(self):
        """Packet truncated at the first sub-packet"""

        with io.BytesIO(b'\x01') as fd:
            reader = PacketReader(fd)

            self.assertEqual(reader.read(), b'')
            self.assertTrue(reader.end_of_packet)
            self.assertEqual(reader.truncated, 2) # 1 byte of sub-packet, and the end of packet marker missing

            self.assertEqual(fd.tell(), 1)

        with io.BytesIO(b'\x02a') as fd:
            reader = PacketReader(fd)

            self.assertEqual(reader.read(), b'a')
            self.assertTrue(reader.end_of_packet)
            self.assertEqual(reader.truncated, 2) # 1 byte of sub-packet, and the end of packet marker missing

            self.assertEqual(fd.tell(), 2)

        with io.BytesIO(b'\x04ab') as fd:
            reader = PacketReader(fd)

            self.assertEqual(reader.read(1), b'a')
            self.assertEqual(reader.read(), b'b')
            self.assertTrue(reader.end_of_packet)
            self.assertEqual(reader.truncated, 3) # 2 bytes of sub-packet, and the end of packet marker missing

            self.assertEqual(fd.tell(), 3)
