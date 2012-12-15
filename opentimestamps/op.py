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

"""Supported operations

Operations objects (class Op) are all immutable. Don't mess with that.

"""

import binascii

def _hexlify(b):
    return binascii.hexlify(b).decode('utf8')
def _unhexlify(h):
    return binascii.unhexlify(h.encode('utf8'))

import opentimestamps.crypto

op_classes_by_name = {}

def register_op(cls):
    op_classes_by_name[cls.__name__] = cls
    return cls

class Op(bytes):
    """Base class for operations

    input - Input bytes this operation works on.
    parents - Byte sequences we have designated as this operations parents.

    """

    @property
    def input(self):
        return self._input

    @classmethod
    def _calculate_digest_from_input(cls, input, **kwargs):
        return input

    def __new__(cls, *inputs, parents=None, digest=None, **kwargs):
        input = b''.join(inputs)
        self = bytes.__new__(cls, cls._calculate_digest_from_input(input, digest=digest, **kwargs))

        if digest is not None:
            assert self == digest

        self._input = input

        if parents is None:
            parents = inputs

        normed_parents = set()
        for p in parents:
            if not isinstance(p,bytes):
                (start,length) = p
                assert length > 0
                normed_parents.add(self.input[start:start+length])
            else:
                normed_parents.add(p)
        self.parents = normed_parents

        return self


    def __repr__(self):
        return '%s(<%s>)' % (self.__class__.__name__,_hexlify(self[0:8]))

    def to_primitives(self):
        parents = []
        for p in self.parents:
            parents.append((self.input.find(p),len(p)))

        d = dict(input=_hexlify(self.input),
                 parents=parents,
                 digest=_hexlify(self))

        return {self.__class__.__name__:d}


    @staticmethod
    def from_primitives(primitive):
        assert len(primitive.keys()) == 1
        cls_name = tuple(primitive.keys())[0]
        kwargs = primitive[cls_name]

        cls = op_classes_by_name[cls_name]
        return cls._from_primitives(**kwargs)

    @classmethod
    def _from_primitives(cls,**kwargs):
        input = _unhexlify(kwargs.pop('input'))

        if 'digest' in kwargs:
            kwargs['digest'] = _unhexlify(kwargs['digest'])

        return cls(input,**kwargs)

@register_op
class Digest(Op):
    """Operation that simply produces a specific digest

    Think of this as a place-holder for an operation. Included to be able to
    assign metadata to digests when we don't have further information about
    them yet.
    """
    @classmethod
    def _calculate_digest_from_input(cls, input, digest=None, **kwargs):
        if not digest:
            raise ValueError('digest must be given and not empty')
        if input != b'':
            raise ValueError('Digest operations have no inputs')

        return digest


@register_op
class Hash(Op):
    @property
    def algorithm(self):
        return self._algorithm

    def __new__(cls, *inputs, algorithm='sha256d', **kwargs):
        assert algorithm in opentimestamps.crypto.hash_functions_by_name
        self = super().__new__(cls, *inputs, algorithm=algorithm, **kwargs)
        self._algorithm = algorithm
        return self

    @classmethod
    def _calculate_digest_from_input(cls, input, algorithm='sha256d', **kwargs):
        return opentimestamps.crypto.hash_functions_by_name[algorithm](input)

    def to_primitives(self):
        r = super().to_primitives()
        r['Hash']['algorithm'] = self.algorithm
        return r
