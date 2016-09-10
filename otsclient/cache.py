# Copyright (C) 2016 The OpenTimestamps developers
#
# This file is part of the OpenTimestamps Client.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of the OpenTimestamps Client including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import os

from opentimestamps.core.timestamp import Timestamp
from opentimestamps.core.serialize import StreamSerializationContext, StreamDeserializationContext

from bitcoin.core import b2x

class TimestampCache:
    """Persistant cache of timestamps"""

    def __init__(self, path):
        self.path = path

        if path is not None:
            # Simple version scheme
            try:
                with open(self.path + '/version', 'r') as fd:
                    try:
                        major, minor = fd.read().strip().split('.')
                        major = int(major)
                        minor = int(minor)
                        if major != 1:
                            raise Exception
                    except Exception:
                        raise Exception("Unknown timestamp cache version")

            except FileNotFoundError:
                os.makedirs(self.path, exist_ok=True)
                with open(self.path + '/version', 'w') as fd:
                    fd.write('%d.%d\n' % (1,0))

    def __commitment_to_filename(self, commitment):
        assert len(commitment) >= 20
        return (self.path + '/' +
                b2x(commitment[0:1]) + '/' +
                b2x(commitment[1:2]) + '/' +
                b2x(commitment[2:3]) + '/' +
                b2x(commitment[3:4]) + '/' +
                b2x(commitment))

    def __contains__(self, commitment):
        try:
            self[commitment]
            return True
        except KeyError:
            return False

    def __getitem__(self, commitment):
        if self.path is None:
            raise KeyError

        elif len(commitment) > 64: # FIXME: hack to avoid filename-too-long errors
            raise KeyError

        try:
            with open(self.__commitment_to_filename(commitment), 'rb') as stamp_fd:
                ctx = StreamDeserializationContext(stamp_fd)
                stamp = Timestamp.deserialize(ctx, commitment)
                return stamp
        except FileNotFoundError:
            raise KeyError

    def __save(self, timestamp):
        if self.path is None:
            return

        # FIXME: should do this atomically
        path = self.__commitment_to_filename(timestamp.msg)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(self.__commitment_to_filename(timestamp.msg), 'wb') as stamp_fd:
            ctx = StreamSerializationContext(stamp_fd)
            timestamp.serialize(ctx)

    def merge(self, new_timestamp):
        try:
            existing = self[new_timestamp.msg]
        except KeyError:
            existing = Timestamp(new_timestamp.msg)

        existing.merge(new_timestamp)
        self.__save(existing)
