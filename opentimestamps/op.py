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

import functools
@functools.total_ordering
class Op:
    """Base class for operations

    input   - Input bytes this operation works on.
    digest  - Output of this operation.

    """

    @property
    def input(self):
        return self._input

    _digest = None
    @property
    def digest(self):
        if self._digest is None:
            self._digest = self.calculate_digest()
        return self._digest

    def __init__(self,*inputs,input=None,digest=None,**kwargs):
        if inputs and input:
            raise TypeError('Input must be specified as either positional arguments, or using input kwarg, not both')
        elif input and not inputs:
            inputs = (input,)

        input = []
        for i in inputs:
            if isinstance(i,bytes):
                input.append(i)
            elif isinstance(i,Op):
                input.append(i.digest)
            else:
                raise TypeError('Op input must be bytes or Op instances')
        self._input = b''.join(input)

    def __repr__(self):
        return '%s(<%s>)' % (self.__class__.__name__,_hexlify(self.digest[0:8]))

    def __eq__(self,other):
        if not isinstance(other,Op):
            return False
        else:
            return self.digest == other.digest

    def __lt__(self,other):
        if not isinstance(other,Op):
            return NotImplemented
        else:
            return self.digest < other.digest

    def __hash__(self):
        return hash(self.digest)

    def to_primitives(self):
        d = dict(input=_hexlify(self.input),
                 digest=_hexlify(self.digest))
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
        kwargs['input'] = _unhexlify(kwargs['input'])

        if 'digest' in kwargs:
            kwargs['digest'] = _unhexlify(kwargs['digest'])

        return cls(**kwargs)

@register_op
class Digest(Op):
    @property
    def algorithm(self):
        return self._algorithm

    def __init__(self,*inputs,digest=None,**kwargs):
        self._digest = digest
        super().__init__(*inputs,**kwargs)

    def to_primitives(self):
        r = super().to_primitives()
        r['Digest']['digest'] = _hexlify(self.digest)
        return r

@register_op
class Hash(Op):
    @property
    def algorithm(self):
        return self._algorithm

    def __init__(self,*inputs,algorithm='sha256d',**kwargs):
        self._algorithm = algorithm
        assert algorithm in opentimestamps.crypto.hash_functions_by_name
        super().__init__(*inputs,**kwargs)

    def calculate_digest(self):
        return opentimestamps.crypto.hash_functions_by_name[self.algorithm](self.input)

    def to_primitives(self):
        r = super().to_primitives()
        r['Hash']['algorithm'] = self.algorithm
        return r


@register_op
class Verify(Op):
    @property
    def method(self):
        return self._method

    @property
    def identity(self):
        return self._identity

    def __init__(self,method=None,identity=None,**kwargs):
        assert isinstance(method,str)
        self._method = method

        assert isinstance(identity,str)
        self._identity = identity

        super().__init__(**kwargs)

    def calculate_digest(self):
        return self.input

    def to_primitives(self):
        r = super().to_primitives()
        r['Verify']['method'] = self.method
        r['Verify']['identity'] = self.identity
        return r

    @classmethod
    def _from_primitives(cls,**kwargs):
        return super().from_primitives(kwargs)
