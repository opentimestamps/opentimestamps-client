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

"""Core data structures to work with directed acyclic graphs of operations

Operations objects (class Op) are all immutable. Don't mess with that.

Note: read opentimestamps-server/doc/design.md

"""

import collections
import copy
import binascii

from ._internal import hexlify,unhexlify

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
        raise NotImplementedError

    def __new__(cls, *inputs, parents=None, digest=None, metadata={}, **kwargs):
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

        self.metadata = dict(metadata)

        return self

    def __repr__(self):
        return '%s(<%s>)' % (self.__class__.__name__,hexlify(self[0:8]))

    def __str__(self):
        return repr(self)

    def to_primitives(self):
        parents = []
        for p in self.parents:
            parents.append((self.input.find(p),len(p)))

        d = dict(input=hexlify(self.input),
                 parents=parents,
                 metadata=self.metadata,
                 digest=hexlify(self))

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
        input = unhexlify(kwargs.pop('input'))

        if 'digest' in kwargs:
            kwargs['digest'] = unhexlify(kwargs['digest'])

        return cls(input,**kwargs)

@register_op
class Digest(Op):
    """Create a Digest

    The Digest is created by concatenating one or more other digests together.
    parents can be specified, however unlike a Hash operation the default is
    for the Digest to have no parents.
    """
    def __new__(cls, *inputs, parents=(), **kwargs):
        return super().__new__(cls, *inputs, parents=parents, **kwargs)

    @classmethod
    def _calculate_digest_from_input(cls, input, **kwargs):
        return input


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
    def pop(self):
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

    def _remove(self,dependent):
        """Ignore write restrictions and remove a dependent from the set anyway"""
        super().remove(dependent)


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
        if not digest_dependents:
            super().pop(digest)
        else:
            digest_dependents._remove(child_op)

    def _add_op(self,op):
        """Add the dependencies of an op"""
        for parent_digest in op.parents:
            self._add_dependency(op,parent_digest)

    def _remove_op(self,op):
        """Remove the dependencies of an op"""
        for parent_digest in op.parents:
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

    The Dag class itself stores operations in memory.

    FIXME: the more advanced set stuff might not work
    """

    def clear(self):
        """Remove all operations from the Dag"""
        self.dependents = DependentsMap()

        # This is a little strange... it's a dict whose key and value is the
        # same.
        self._ops_by_op = {}

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

    def pop(self):
        raise NotImplementedError # FIXME

    def remove(self,op):
        """Remove an operation from the dag

        Raises a KeyError is the operation is not a part of the dag.
        """
        if op not in self:
            raise KeyError

        self._ops_by_op.pop(op)
        super().remove(op)
        self.dependents._remove_op(op)


    def discard(self,op):
        """Same as set.discard()"""
        try:
            self.remove(op)
        except KeyError:
            pass


    def _add_unconditionally(self,new_op):
        """Low-level add implementation

        This just needs to do the add; dependencies are handled by
        add_unconditionally()
        """
        self._ops_by_op[new_op] = new_op
        super(Dag,self).add(new_op)


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

        Basically Digest-not-in-dag < Digest-in-dag < Hash

        Operations other than Digests always replace Digest operations in the
        Dag.
        """
        # Coerce to an Op
        if not isinstance(new_op, Op):
            new_op = Digest(new_op)

        try:
            existing_op = self[new_op]
        except KeyError:
            self.add_unconditionally(new_op)
            return new_op

        # Decide who has the better operation
        r = None
        merge_src = None
        if isinstance(new_op, Hash) and isinstance(existing_op, Hash):
            assert new_op == existing_op
            assert new_op.algorithm == existing_op.algorithm

            # Both parties have a Hash, however the new_op may have
            # information about new parent slices.
            existing_op.parents.update(new_op.parents)
            merge_src = new_op
            r = existing_op

        elif isinstance(new_op, Hash):
            # We don't have a Hash, but the callee does. Their Op provides more
            # information than our op, so replace ours with theirs. We
            # shouldn't have any parents; if we do that implies there is more
            # than one way to calculate this digest.
            assert not existing_op.parents
            self.add_unconditionally(new_op)
            merge_src = existing_op
            r = new_op

        elif isinstance(existing_op, Hash):
            # We have a Hash, they don't. We win.
            merge_src = new_op
            r = existing_op

        elif existing_op == new_op:
            # Both parties have an equivalent non-Digest object. Merge parents.
            existing_op.parents.update(new_op.parents)
            merge_src = new_op
            r = existing_op

        else:
            # This shouldn't happen even if a hash function is broken because
            # Op's are compared by their digest
            assert False

        r.metadata.update(merge_src.metadata)
        return r


    def path(self,start,dest,chain=None):
        """Find a path from start to dest

        start - digest, can be outside the dag, provided an operation in the
                dag has the digest as one of its parents.

        dest  - Either a digest or a Notary

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

    def children(self,parents,all_children=None):
        """Find all children of a set of parents"""
        if all_children is None:
            all_children = set()

        for parent in parents:
            not_yet_visited = self.dependents[parent].difference(all_children)
            all_children.update(not_yet_visited)
            self.children(not_yet_visited,all_children)

        return all_children


def build_merkle_tree(parents, algorithm=None, _accumulator=None):
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

            # Make sure parent is in fact an Op. Not really sure if this is the
            # right place for this...
            if not isinstance(p1,Op):
                p1 = Digest(p1)
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
            if not isinstance(p2,Op):
                p2 = Digest(p2)
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
            h = Hash(p1,p2,algorithm=algorithm)
        else:
            h = Hash(p1,p2) # let it use the default

        accumulator.append(h)
