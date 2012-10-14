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

"""Core data structures to work with the dag

Note: read opentimestamps-server/doc/design.md

The timestamping problem can scale pretty well, so we can afford to be
relatively wasteful in the implementation specifics, provided that everything
we do maintains scalability; avoid micro-optimizations.

Operations objects (class Op) can all be immutable. Don't mess with that. We
use __getattr__-type stuff to enforce this.

"""

import binascii
import collections
import copy
import hashlib
import time
import re

from . import serialization
from . import notary

# Operations - edges in DAG
# Digests - vertexes in DAG

def register_Op(cls):
    cls.digested_attributes = cls.op_arguments
    serialization.digestible_serialized_object_subclass('ots.dag')(cls)
    return cls


class Op(serialization.DigestibleSerializedObject):
    """Base class for operations

    Attributes
    ----------

    inputs - Immutable ordered set of references to the digests this operation
             depends on. Op() in Op().inputs will be implemented efficiently.
             Note that a two-element tuple is an efficient implementation.

    digest - Immutable bytes of the output digest.

    op_arguments - List of other immutable arguments this Operation depends on.

    Op-subclass instances may have other attributes, but if they aren't in
    op_arguments, they're not considered in equality testing between instances.
    Of course, since .digest depends on the arguments, equality testing reduces
    to a.digest == b.digest

    Equality testing
    ----------------

    Op-subclass instances are considered equal if their .digests are equal.
    This is true even if they aren't even the same sub-class.


    Proxies
    -------

    Op-subclass instances may be proxied. This is useful in the server dag
    implementation. isinstance(Op) and so on is guaranteed to work.
    """
    op_name = 'Op'
    op_arguments = ('inputs',)
    serialized_attributes = ('digest','inputs')

    def __init__(self,inputs=(),digest=None,**kwargs):
        super().__init__(**kwargs)

        normalized_inputs = []
        for i in inputs:
            try:
                normalized_inputs.append(i.digest)
            except AttributeError:
                normalized_inputs.append(i)
        self.inputs = tuple(normalized_inputs)

        self.lock()

        if digest is not None and self.digest != digest:
            assert False


    def __repr__(self):
        return '%s(<%s>)' % (self.__class__.__name__,binascii.hexlify(self.digest[0:8]))

    def _swap_input_obj(self,better_input):
        """Swap an input object with a better object"""
        for obj,i in enumerate(self.inputs):
            if obj == better_input:
                self.inputs[i] = better_input


# Done here to avoid needing a forward declaration
Op = register_Op(Op)

@register_Op
class Digest(Op):
    op_name = 'Digest'
    op_arguments = ()
    serialized_attributes = ()

    def calculate_digest(self):
        return self.__fixed_digest

    def __init__(self,digest=None,inputs=(),**kwargs):
        if digest is None:
            raise ValueError('Must specify digest value')
        elif isinstance(digest,bytes):
            pass
        elif isinstance(digest,Op):
            digest = digest.digest
        else:
            raise TypeError('digest must be of type bytes or Op subclass')

        if len(inputs) > 0:
            raise ValueError("Digest Op's can not have inputs")

        self.__fixed_digest = digest
        super().__init__(digest=digest,inputs=inputs,**kwargs)


@register_Op
class Hash(Op):
    op_name = 'Hash'
    op_arguments = ('algorithm',)
    serialized_attributes = ('algorithm',)

    def __init__(self,algorithm='sha256',**kwargs):
        if algorithm not in ('sha256','sha1','sha512','crc32'):
            raise ValueError('Unsupported hash algorithm %s' % algorithm)
        self.algorithm = algorithm

        super(Hash,self).__init__(algorithm=algorithm,**kwargs)


    def calculate_digest(self):
        hash_fn = None
        if self.algorithm == 'crc32':
            # Quick-n-dirty crc32 implementation
            class hash_crc32(object):
                def update(self,newdata):
                    self.crc = binascii.crc32(newdata,self.crc)
                def __init__(self,data=b''):
                    self.crc = 0
                    self.update(data)
                def digest(self):
                    import struct
                    return struct.pack('>L',self.crc)
            hash_fn = hash_crc32
        else:
            hash_fn = getattr(hashlib,self.algorithm)

        h = hash_fn()
        for i in self.inputs:
            h.update(i)

        # Ugly way of determining if we need to hash things twice.
        if self.algorithm[0:3] == 'sha':
            return hash_fn(h.digest()).digest()
        else:
            return h.digest()


# Timestamps are interpreted as microseconds since the epoch, mainly so
# javascript can represent timestamps exactly with it's 2^53 bits available for
# ints.
def time_to_timestamp(t):
    return int(t * 1000000)

def time_from_timestamp(t):
    return t / 1000000.0

@register_Op
class Verify(Op):
    op_name = 'Verify'
    op_arguments = ('signature',)
    serialized_attributes = ('signature',)

    def __init__(self,
            inputs=(),
            signature = notary.Signature(),
            **kwargs):

        if len(inputs) != 1:
            raise ValueError('Verify operations must have exactly one input, got %d' % len(inputs))

        self.signature = signature

        super(Verify,self).__init__(inputs=inputs,**kwargs)


    def calculate_digest(self):
        return serialization.binary_serialize(self.signature)

    def verify(self):
        raise TypeError("Can't verify; unknown notary method %s" % self.notary_method)



class DigestDependents(set):
    """The set of dependents for a digest

    This acts like a frozenset of Op's.
    """
    def __init__(self):
        super(DigestDependents,self).__init__()

    # Act like a frozenset
    def _raise_readonly_error(self):
        raise NotImplementedError("The set of dependents for a digest is calculated and can not be changed directly.")
    def add(self,other):
        self._raise_readonly_error()
    def clear(self,other):
        self._raise_readonly_error()
    def difference_update(self,other):
        self._raise_readonly_error()
    def discard(self,other):
        self._raise_readonly_error()
    def intersection_update(self,other):
        self._raise_readonly_error()
    def pop(self,other):
        self._raise_readonly_error()
    def remove(self,other):
        self._raise_readonly_error()
    def symmetric_difference_update(self,other):
        self._raise_readonly_error()
    def update(self,other):
        self._raise_readonly_error()

    def _add(self,dependent):
        """Ignore write restrictions and add a dependent to the set anyway"""
        super(DigestDependents,self).add(dependent)


class DependentsMap(dict):
    """Map digests and their dependents

    Found in the dependents attribute of Dag-subclass instances.

    This is a defaultdict-like whose keys are digests that are depended on by
    operations in the dag. The value for a given key is defined as the set of
    all such operations; any key will at least map to an empty set. These sets
    are frozen and can not be changed directly.
    """

    # Included for use by subclasses
    _DigestDependents_instantiator = DigestDependents

    def __init__(self):
        super(DependentsMap,self).__init__()

    # Disable modifications
    def _raise_readonly_error(self):
        raise NotImplementedError("Dependency information is calculated and can not be changed directly")
    def __setitem__(self,key,value):
        self._raise_readonly_error()
    def clear(self,key,value):
        self._raise_readonly_error()
    def pop(self,key,value):
        self._raise_readonly_error()
    def popitem(self,key,value):
        self._raise_readonly_error()
    def setdefault(self,key,value):
        self._raise_readonly_error()
    def update(self,key,value):
        self._raise_readonly_error()


    def __contains__(self,other):
        try:
            return other.digest in self
        except AttributeError:
            return super(DependentsMap,self).__contains__(other)

    def __getitem__(self,key):
        try:
            return self[key.digest]
        except AttributeError:
            try:
                return super(DependentsMap,self).__getitem__(key)
            except KeyError:
                return frozenset()

    def _add_dependency(self,child_op,digest):
        """Add op child as a dependency of digest"""
        digest_dependents = \
                super(DependentsMap,self).setdefault(digest,
                        self._DigestDependents_instantiator())
        digest_dependents._add(child_op)

    def _remove_dependency(self,child_op,digest):
        """Remove op child as a dependency of digest"""
        try:
            digest_dependents = super(DependentsMap,self).__getitem__(digest)
        except KeyError:
            return
        digest_dependents.pop(child_op)
        if not digest_dependents:
            super(DependentsMap,self).pop(digest)

    def _add_op(self,op):
        """Add the dependencies of an op"""
        for parent_digest in op.inputs:
            self._add_dependency(op,parent_digest)

    def _remove_op(self,op):
        """Remove the dependencies of an op"""
        for parent_digest in op.inputs:
            self._remove_dependency(op,parent_digest)


class Dag(set):
    """Store the directed acyclic graph of operations

    Dag's also provide access to dependency information, as well as methods to
    search for paths in the graph.

    Dag's are set-subclasses and behave essentially just like sets. Membership
    is defined by digest. A Dag with a Hash operation hash_op whose digest is
    'foo' will return true for the following:

        hash_op in dag
        Digest('foo') in dag

    In addition Dag's support indexing to allow the actual stored object to be
    retrieved:

        hash_op is dag[hash_op]
        hash_op is dag[Digest('foo')]

    Queries by raw bytes are not coerced; use Digest(bytes) instead.

    dependents    - A DependentsMap
    verifications - The set of all Verify operations in the dag.

    The Dag class itself stores operations in memory.

    FIXME: the more advanced set stuff might not work
    """

    def clear(self):
        """Remove all operations from the Dag"""
        self.dependents = DependentsMap()

        # This is a little strange... it's a dict whose key and value is the
        # same.
        self._ops_by_op = {}

        self.verifications = set()
        super(Dag,self).clear()


    def __init__(self,iterable=()):
        super(Dag,self).__init__(self)
        self.clear()
        self.update(iterable)

    def __getitem__(self,key):
        return self._ops_by_op[key]

    def update(self,iterable):
        """Update the dag with a union of itself and others"""
        for i in iterable:
            self.add(i)

    def _remove_verification(self,new_verify_op):
        """Called for each Verify operation removed

        This is called before anything else happens.
        """
        self.verifications.remove(new_verify_op)

    def pop(self,op):
        """Remove an operation from the dag

        Raises a KeyError is the operation is not a part of the dag.
        """
        if op not in self:
            raise KeyError

        if isinstance(op,Verify):
            self._add_verification(op)
        self._ops_by_op.pop(op)
        super(Dag,self).remove(op)
        self.dependents._remove_op(op)


    def discard(self,op):
        """Same as set.discard()"""
        try:
            self.pop(op)
        except KeyError:
            pass


    def _add_verification(self,new_verify_op):
        """Called for each new Verify operation added

        This is called just before add() returns; the op will be in the dag.
        """
        self.verifications.add(new_verify_op)


    def _add_unconditionally(self,new_op):
        """Low-level add implementation

        This just needs to do the add; dependencies are handled by
        add_unconditionally()
        """
        self._ops_by_op[new_op] = new_op
        super(Dag,self).add(new_op)

        if isinstance(new_op,Verify):
            self._add_verification(new_op)


    def add_unconditionally(self,new_op):
        """Add an operation to the Dag, unconditionally

        If the Dag already includes an operation with the same digest, that
        operation will be replaced.

        Returns nothing.
        """
        self.discard(new_op)
        self._add_unconditionally(new_op)

        self.dependents._add_op(new_op)


    def add(self,new_op):
        """Add an operation to the Dag

        This will return the 'best' operation object to use to work with this
        dag. This will be different from what you added if the Dag already
        includes an operation with the same digest, and that operation already
        has as much, or more, information on how the digest was calculated.

        Basically Digest-not-in-dag < Digest-in-dag < Hash/Verify/etc

        Operations other than Digests always replace Digest operations in the
        Dag.
        """
        try:
            existing_op = self[new_op]
        except KeyError:
            self.add_unconditionally(new_op)
            return new_op

        # Decide who has the better operation
        if isinstance(new_op,Digest):
            # Callee has a plain Digest, we have something else. If it's not a
            # Digest, what we have is better because it has more information.
            # If it's just a Digest, what we have is still better to promote
            # object re-use.
            return existing_op

        elif isinstance(existing_op,Digest):
            # We have a Digest, callee has something more interesting. Use
            # callee's new object instead of ours.
            self.add_unconditionally(new_op)
            return new_op

        elif existing_op == new_op:
            # Both parties have an equivalent non-Digest object.
            return existing_op

        else:
            # This shouldn't happen even if a hash function is broken because
            # Op's are compared by their .digest
            assert False

    def path(self,start,dest,chain=None):
        """Find a path from start to dest

        start - digest, can be outside the dag, provided an operation in the
                dag has the digest as one of its inputs. 

        dest  - Either a digest or a NotarySpecification

        The returned path includes the destination, and every operation needed
        to recalculate the destination. Note that if the destination matches
        the starting point, path() will always return exactly the destination;
        what is in the dag is irrelevant.

        Returns None if the path can not be found.
        """
        def op_matches_target(op,target):
            if op == target:
                return True
            try:
                return op.signature.notary == target
            except AttributeError:
                return False


        # Handle the stupid case of the callee calling with start == dest
        if chain is None and op_matches_target(start,dest):
            return (dest,)

        if op_matches_target(start,dest):
            # Path found!
            #
            # Turn the chain back into a linked list
            r = []
            while chain is not None:
                r.append(chain[1])
                chain = chain[0]
            return reversed(r)

        for dependent in self.dependents[start]:
            assert dependent in self
            p = self.path(dependent,dest,chain=(chain,dependent))
            if p is not None:
                return p

        return None


def build_merkle_tree(parents,algorithm=None,_accumulator=None):
    """Build a merkle tree

    parents   - iterable of all the parents you want in the tree.
    algorithm - will be passed to Hash if set.

    Returns an iterable of all the intermediate digests created, and the final
    child, which will be at the end. If parents has exactly one item in it,
    that parent is the merkle tree child.
    """

    accumulator = _accumulator
    if accumulator is None:
        accumulator = []
        parents = iter(parents)

    next_level_starting_idx = len(accumulator)

    while True:
        try:
            p1 = next(parents)
        except StopIteration:
            # Even number of items, possibly zero.
            if len(accumulator) == 0 and _accumulator is None:
                # We must have been called with nothing at all.
                raise ValueError("No parent digests given to build a merkle tree from""")
            elif next_level_starting_idx < len(accumulator):
                return build_merkle_tree(iter(accumulator[next_level_starting_idx:]),
                        _accumulator=accumulator,algorithm=algorithm)
            else:
                return accumulator

        try:
            p2 = next(parents)
        except StopIteration:
            # We must have an odd number of elements at this level, or there
            # was only one parent.
            if len(accumulator) == 0 and _accumulator is None:
                # Called with exactly one parent
                return (p1,)
            elif next_level_starting_idx < len(accumulator):
                accumulator.append(p1)
                # Note how for an odd number of items we reverse the list. This
                # switches the odd item out each time. If we didn't do this the
                # odd item out on the first level would effectively rise to the
                # top, and have an abnormally short path. This also makes the
                # overall average path length slightly shorter by distributing
                # unfairness.
                return build_merkle_tree(iter(reversed(accumulator[next_level_starting_idx:])),
                        _accumulator=accumulator,algorithm=algorithm)
            else:
                return accumulator

        h = None
        if algorithm is not None:
            h = Hash(inputs=(p1,p2),algorithm=algorithm)
        else:
            h = Hash(inputs=(p1,p2)) # let it use the default

        accumulator.append(h)
