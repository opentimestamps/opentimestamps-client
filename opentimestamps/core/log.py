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

from opentimestamps.core.op import CryptOp
from opentimestamps.core.serialize import (
    BadMagicError, DeserializationError, StreamSerializationContext, StreamDeserializationContext
)
from opentimestamps.core.packetstream import PacketReader, PacketWriter, PacketMissingError


class TimestampLog:
    """Timestamps for append-only files

    With append-only files such as log files, rather than timestamping once, you
    want to timestamp them repeatedly as new data is appended to them. Logfile
    timestamps support this usecase by allowing multiple timestamps on the same
    file to be recorded, with each timestamp including the length of the log file
    at the time that particular timestamp was created.

    In addition, logfile timestamps are serialized such that they themselves can be
    written to append-only storage.
    """

    HEADER_MAGIC = b'\x00OpenTimestamps\x00\x00Log\x00\xd9\x19\xc5\x3a\x99\xb1\x12\xe9\xa6\xa1\x00'


class TimestampLogReader(TimestampLog):

    @classmethod
    def open(cls, fd):
        """Open an existing timestamp log

        fd must be positioned at the start of the log; the header will be
        immediately read and DeserializationError raised if incorrect.
        """
        ctx = StreamDeserializationContext(fd)

        actual_magic = ctx.read_bytes(len(cls.HEADER_MAGIC))

        if cls.HEADER_MAGIC != actual_magic:
            raise BadMagicError(cls.HEADER_MAGIC, actual_magic)

        file_hash_op = CryptOp.deserialize(ctx)

        return cls(fd, file_hash_op)


    def __init__(self, fd, file_hash_op):
        """Create a timestamp log reader instance

        You probably want to use TimestampLogReader.open() instead.
        """
        self.fd = fd
        self.file_hash_op = file_hash_op

    def __iter__(self):
        """Iterate through all timestamps in the timestamp log"""
        while True:
            try:
                reader = PacketReader(self.fd)
            except PacketMissingError:
                break

            ctx = StreamDeserializationContext(reader)

            try:
                length = ctx.read_varuint()
                file_hash = ctx.read_bytes(self.file_hash_op.DIGEST_LENGTH)
                timestamp = Timestamp.deserialize(ctx, file_hash)
                yield (length, timestamp)
            except DeserializationError as exp:
                # FIXME: should provide a way to get insight into these errors
                pass



class TimestampLogWriter(TimestampLog):

    @classmethod
    def open(cls, fd):
        """Open an existing timestamp log for writing

        fd must be both readable and writable, and must be positioned at the
        beginning of the timestamp log file. The header will be immediately
        read, with BadMagicError raised if it's incorrect.
        """

        # Use the log reader to read the header information
        reader = TimestampLogReader.open(fd)

        # Parse the entries to find the last one
        for stamp in reader:
            pass

        # FIXME: pad the end as necessary to deal with trucated writes

        return cls(fd, reader.file_hash_op)

    @classmethod
    def create(cls, fd, file_hash_op):
        """Create a new timestamp log

        Writes the header appropriately.
        """
        ctx = StreamSerializationContext(fd)

        ctx.write_bytes(cls.HEADER_MAGIC)
        file_hash_op.serialize(ctx)

        return cls(fd, file_hash_op)


    def __init__(self, fd, file_hash_op):
        """Create a new timestamp log writer

        You probably want to use the open() or create() methods instead.
        """

        self.fd = fd
        self.file_hash_op = file_hash_op

    def append(self, length, timestamp):
        """Add a new timestamp to the log"""
        if len(timestamp.msg) != self.file_hash_op.DIGEST_LENGTH:
            raise ValueError("Timestamp msg length does not match expected digest length; %d != %d" % (len(timestamp.msg), self.file_hash_op.DIGEST_LENGTH))

        with PacketWriter(self.fd) as packet_fd:
            ctx = StreamSerializationContext(packet_fd)
            ctx.write_varuint(length)
            ctx.write_bytes(timestamp.msg)
            timestamp.serialize(ctx)
