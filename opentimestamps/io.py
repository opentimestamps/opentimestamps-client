# Copyright (C) 2012 Peter Todd <pete@petertodd.org>
#
# This file is part of the OpenTimestamps Client.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution and at http://opentimestamps.org
#
# No part of the OpenTimestamps Client, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import io
import json

import opentimestamps.timestamp

class TimestampFile(opentimestamps.timestamp.Timestamp):
    def __new__(cls, in_fd=None, out_fd=None, data_fd=None, **kwargs):
        if in_fd is not None:
            in_fd = io.TextIOWrapper(in_fd, encoding='utf8')
            self = cls.from_primitives(json.load(in_fd), data_fd=data_fd)
            self.in_fd = None
            self.out_fd = out_fd
            return self
        else:
            super().__new__(cls, in_fd=in_fd, out_fd=out_fd, **kwargs)

    def __init__(self, in_fd=None, out_fd=None, **kwargs):
        super().__init__(**kwargs)

        assert in_fd is None
        self.out_fd = io.TextIOWrapper(out_fd, encoding='utf8')

    def write(self):
        json.dump(self.to_primitives(), self.out_fd, indent=4)
