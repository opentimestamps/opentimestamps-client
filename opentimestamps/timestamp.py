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

import opentimestamps.crypto

from opentimestamps._internal import hexlify,unhexlify
from opentimestamps.dag import Op,Dag,Hash
from opentimestamps.notary import Signature

class TimestampError(Exception):
    pass

class TimestampVerificationError(TimestampError):
    pass

class Timestamp:
    def __init__(self, data_fd=None, digests=None, ops=(), signatures=(), context=None):
        self.data_fd = data_fd
        self.dag = Dag(ops)
        if digests is None:
            digests = {}
        self.digests = digests
        self.signatures = list(signatures)
        self.context = context

    def add_algorithms(self, *algorithms):
        """Add algorithms to the timestamp

        The algorithms will be added to the set of existing algorithms. The
        data will be hashed with *all* specified algorithms, not just the new
        ones, to ensure consistency.
        """
        hashers = []
        for algo in set(self.digests.keys()).union(algorithms):
            hashers.append(opentimestamps.crypto.hash_functions_by_name[algo].incremental(b''))

        while True:
            next_bytes = self.data_fd.read(io.DEFAULT_BUFFER_SIZE)
            if len(next_bytes) == 0:
                break
            else:
                for hasher in hashers:
                    hasher.update(next_bytes)

        for hasher in hashers:
            digest = hasher.digest()

            if hasher.name not in self.digests:
                self.digests[hasher.name] = digest
            else:
                # Check existing digest
                if self.digests[hasher.name] != digest:
                    # FIXME: better error message
                    raise TimestampVerificationError('Got different digest than saved for algorithm {}'.format(hasher.name))

    def get_digest_to_sign(self, algorithm, use_nonce=True):
        pass

    def verify_data(self):
        """Verify that the data being timestamped matches the digests saved"""
        self.add_algorithms()

    def verify_consistency(self):
        """Verify consistency of the dag

        Ensures that every signature can be connected to a digest
        """
        digest_children = self.dag.children(self.digests.values())
        digest_children.update(self.digests.values())

        for sig in self.signatures:
            if not sig.digest in digest_children:
                raise TimestampVerificationError('No path to signature {}'.format(sig))

    def to_primitives(self):
        d = dict(digests = {algo:hexlify(digest) for (algo,digest) in self.digests.items()},
                 ops = [op.to_primitives() for op in self.dag],
                 signatures = [sig.to_primitives() for sig in self.signatures])
        return d

    @classmethod
    def from_primitives(cls, primitives, data_fd=None):
        digests = {algo:unhexlify(digest) for (algo,digest) in primitives['digests'].items()}
        ops = [Op.from_primitives(op) for op in primitives['ops']]
        signatures = [Signature.from_primitives(sig) for sig in primitives['signatures']]
        return Timestamp(ops=ops, signatures=signatures, digests=digests, data_fd=data_fd)
