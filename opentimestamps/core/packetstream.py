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
import sys

"""Packet-writing support for append-only streams with truncation handling

Strictly append-only streams, such as files whose append-only attribute has
been set by chattr(1), are a useful way to avoid losing data. But using them
for complex serialized data poses a problem: truncated writes.

For instance, suppose we try to serialize the string 'Hello World!' to a stream
using var_bytes(). If everything goes correctly, the following will be written
to the stream:

    b'\x0cHello World!'

However, suppose that there's an IO error after the third byte, leaving the
file truncated:

    b'\x0cHe'

Since the stream is strictly append-only, if we write anything else to the
stream, the length byte will cause the deserializer to later incorrectly read
part of the next thing we write as though it were part of the original string.
While in theory we could fix this, doing so requires a lot of invasive code
changes to the (de)serialization code.

This module implements a much simpler solution with variable length packets.
Each packet can be any length, and it's guaranteed that in the event of a
truncated write, at worst the most recently written packet will be corrupted.
Secondly, it's guaranteed that in the event of a corrupt packet, additional
packets can be written succesfully even if the underlying stream is
append-only.
"""


class PacketWriter(io.BufferedIOBase):
    """Write an individual packet"""

    def __init__(self, fd):
        """Create a new packet stream for writing

        fd must be a buffered stream; a io.BufferedIOBase instance.

        FIXME: fd must be blocking; the BlockingIOError exception isn't handled
        correctly yet
        """
        if not isinstance(fd, io.BufferedIOBase):
            raise TypeError('fd must be buffered IO')

        self.raw = fd
        self.pending = b''

    def write(self, buf):
        if self.closed:
            raise ValueError("write to closed packet")

        pending = self.pending + buf

        # the + 1 handles the case where the length of buf is an exact multiple
        # of the max sub-packet size
        for i in range(0, len(pending) + 1, 255):
            chunk = pending[i:i+255]
            if len(chunk) < 255:
                assert 0 <= len(pending) - i < 255
                self.pending = chunk
                break
            else:
                assert len(chunk) == 255

            try:
                l = self.raw.write(b'\xff' + chunk)
                assert l == 256
            except io.BlockingIOError as exp:
                # To support this, we'd need to look at characters_written to
                # figure out what data from pending has been written.
                raise Exception("non-blocking IO not yet supported: %r" % exp)
        else:
            assert False

        return len(buf)

    def flush_pending(self):
        """Flush pending data to the underlying stream

        All pending data is written to the underlying stream, creating a
        partial-length sub-packet if necessary. However the underlying stream
        is _not_ flushed. If there is no pending data, this function is a
        no-op.
        """
        if self.closed:
            raise ValueError("flush of closed packet")

        if not self.pending:
            return

        assert len(self.pending) < 255

        l = self.raw.write(bytes([len(self.pending)]) + self.pending)
        assert l == 1 + len(self.pending)

        self.pending = b''

        try:
            self.raw.flush()
        except io.BlockingIOError as exp:
            # To support this, we'd need to look at characters_written to
            # figure out what data from pending has been written.
            raise Exception("non-blocking IO not yet supported: %r" % exp)

    def flush(self):
        """Flush the packet to disk

        All pending data is written to the underlying stream with
        flush_pending(), and flush() is called on that stream.
        """
        self.flush_pending()

        try:
            self.raw.flush()
        except io.BlockingIOError as exp:
            # To support this, we'd need to look at characters_written to
            # figure out what data from pending has been written.
            raise Exception("non-blocking IO not yet supported: %r" % exp)

    def close(self):
        """Close the packet

        All pending data is written to the underlying stream, and the packet is
        closed.
        """
        self.flush_pending()
        self.raw.write(b'\x00') # terminator to close the packet

        # Note how we didn't call flush above; BufferedIOBase.close() calls
        # self.flush() for us.
        super().close()

class PacketMissingError(IOError):
    """Raised when a packet is completely missing"""

class PacketReader(io.BufferedIOBase):
    """Read an individual packet"""

    def __init__(self, fd):
        """Create a new packet stream reader

        The first byte of the packet will be read immediately; if that read()
        fails PacketMissingError will be raised.
        """
        self.raw = fd

        # Bytes remaining until the end of the current sub-packet
        l = fd.read(1)
        if not l:
            raise PacketMissingError("Packet completely missing")

        self.len_remaining_subpacket = l[0]

        # Whether the end of the entire packet has been reached
        self.end_of_packet = False

        # How many bytes are known to have been truncated (None if not known yet)
        self.truncated = None

    def read(self, size=-1):
        if self.end_of_packet:
            return b''

        r = []
        remaining = size if size >= 0 else sys.maxsize
        while remaining and not self.end_of_packet:
            if self.len_remaining_subpacket:
                # The current subpacket hasn't been completely read.
                l = min(remaining, self.len_remaining_subpacket)
                b = self.raw.read(l)

                r.append(b)
                self.len_remaining_subpacket -= len(b)
                remaining -= len(b)

                if len(b) < l:
                    # read returned less than requested, so the sub-packet must
                    # be truncated; record how many bytes are missing. Note how
                    # we add one to that figure to account for the
                    # end-of-packet marker.
                    self.truncated = l - len(b) + 1
                    self.end_of_packet = True

            else:
                # All of the current subpacket has been read, so start reading
                # the next sub-packet.

                # Get length of next sub-packet
                l = self.raw.read(1)
                if l == b'':
                    # We're truncated by exactly one byte, the end-of-packet
                    # marker.
                    self.truncated = 1
                    self.end_of_packet = True

                else:
                    # Succesfully read the length
                    self.len_remaining_subpacket = l[0]

                    if not self.len_remaining_subpacket:
                        self.end_of_packet = True

        return b''.join(r)
