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
import hashlib
import time
import re

from . import serialization
from . import notary

# Operations - edges in DAG
# Digests - vertexes in DAG

def register_Op(cls):
    def get_dict_to_serialize(fcls,obj):
        d = obj.__dict__.copy()

        # Inputs are stored as the actual digest values, not Digest objects.
        d['inputs'] = [i.digest for i in obj.inputs]
        return d

    serialization.make_simple_object_serializer(cls,'ots.dag',
            get_dict_to_serialize=get_dict_to_serialize)

    return cls


class Op(object):
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
    op_arguments = ('digest','inputs',)

    def __init__(self,inputs=(),digest=None,**kwargs):
        self.__dict__.update(kwargs)

        normalized_inputs = []
        for i in inputs:
            if isinstance(i,bytes):
                i = Digest(i)
            normalized_inputs.append(i)
        self.inputs = normalized_inputs

        # Want to be sure that digest hasn't been set until now, because
        # otherwise __hash__() can silently return garbage and corrupt things
        # like set() memberships.
        assert not hasattr(self,'digest')

        self.digest = digest
        if self.digest is None:
            self.digest = self.calculate_digest()


    def calculate_digest(self):
        """Calculate the digest

        This method will always calculate the digest from scratch based on the
        inputs and operation arguments.
        """
        raise NotImplementedError


    def __eq__(self,other):
        """Equality comparison.

        Equality is defined by the digests, nothing else. Even different
        sub-classes will compare equal if their digests are equal.
        """
        # It'd be cute to define < and > as which operation is most complex...
        try:
            if isinstance(other,Op):
                return self.digest == other.digest
            else:
                return False
        except AttributeError:
            return False


    def __hash__(self):
        return hash(self.digest)


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

    def __init__(self,digest=None,inputs=()):
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

        super(Digest,self).__init__(digest=digest,inputs=inputs)



@register_Op
class Hash(Op):
    op_name = 'Hash'
    op_arguments = ('algorithm',)

    def __init__(self,algorithm=u'sha256',**kwargs):
        if algorithm not in (u'sha256',u'sha1',u'sha512',u'crc32'):
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
                def __init__(self,data=''):
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
            h.update(i.digest)

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



class Dag(object):
    """Store the directed acyclic graph of digests

    The key thing the Dag provides is the ability to find paths from one digest
    to another. Note that the typical use case, where you have a digest and
    want to find out what sequence of Op's calculates a digest that has been
    timestamped, is exactly the opposite of what data is available. Essentially
    an Op, which computes a digest, has a list of inputs, but we want to go
    from inputs to the Op calculating a digest based on them.

    Thus the Dag keeps track of what Op's are dependent on the digests in the
    dag, but if, and only if, both are stored in the Dag.

    dependents[] - set of dependents for a given digest
    """

    def __contains__(self,other):
        raise NotImplementedError


    def __getitem__(self,digest):
        raise NotImplementedError


    def _add(self,new_digest_obj):
        """Underlying add() implementation"""
        raise NotImplementedError


    def _swap(self,existing_digest_obj,new_digest_obj):
        """Internal function to swap existing with new

        Don't use this; use add()
        """
        raise NotImplementedError


    def add(self,new_digest_obj):
        """Add a digest to the Dag

        Returns the new_digest_obj object you should be using; if the Dag
        contains an Op object that produces the same digest you'll get that
        back instead. There also may be other cases where this happens.
        """
        if new_digest_obj not in self:
            self._add(new_digest_obj)
            return new_digest_obj

        existing_digest_obj = self[new_digest_obj]
        if isinstance(new_digest_obj,Digest):
            # Callee has a plain Digest, we have something else. If it's an Op,
            # what we have is better because it has more information. If it's
            # just a Digest, what we have is still better to promote object
            # re-use.
            return existing_digest_obj

        elif isinstance(existing_digest_obj,Digest):
            # We have a Digest, callee has something more interesting. Use
            # callee's new object instead of ours.
            self._swap(existing_digest_obj,new_digest_obj)
            return new_digest_obj

        elif existing_digest_obj == new_digest_obj:
            # Both parties have an equivalent object, although old is not new
            #
            # FIXME: it'd be good to add some sort of test here to detect
            # broken hash algorithms, or more likely, implementations. It'd
            # probably be cheap too because this case is likely to not come up
            # all that often. I might be wrong though.
            return existing_digest_obj

        else:
            # This shouldn't happen even if a hash function is broken because
            # Op's are compared by their .digest
            assert False

    def digests(self):
        """Returns an iterable of all digests in this Dag

        This may be expensive.
        """
        raise NotImplementedError


    def path(self,start,dest,chain=None):
        """Find a path from start to dest

        start - Digest
        dest  - One of Digest or NotarySpec

        The returned path includes start, and the order is start,...,dest

        Returns None if the path can not be found.

        If the starting digest is not in this dag, that is considered as the
        path not being found, unless the start and destination are the same.
        """

        if chain is None:
            chain = (None,start)

        if start == dest:
            # Path found!
            #
            # Turn the chain back into a linked list
            r = []
            while chain is not None:
                r.append(chain[1])
                chain = chain[0]
            return reversed(r)

        if start not in self:
            return None

        for dependent in self.dependents[start]:
            assert dependent in self
            p = self.path(dependent,dest,chain=(chain,dependent))
            if p is not None:
                return p

        return None



class MemoryDag(Dag):
    digests = None

    def __init__(self):
        # Every digest in the Dag.
        #
        # For each given digest object we store:
        #
        #     self._digests[obj] = obj
        #
        # A bit odd looking, a set is closer to what we want, but we need to be
        # able to retrieve the actual object whose digest matches what we want.
        self._digests = {}

        # parent:set(all Ops in the Dag with parent as an input)
        self.dependents = {}

        # As above, but this time parent is *not* in the Dag. This allows us to
        # later link the dependency of child on parent if the parent is later
        # added to the Dag.
        self._dependents_just_beyond_edge = {}

    def __contains__(self,other):
        try:
            return other.digest in self._digests
        except AttributeError:
            return False


    def __getitem__(self,digest):
        if not isinstance(digest,Op):
            raise TypeError
        else:
            return self._digests[digest.digest]


    def __link_inputs(self,new_digest_obj):
        for i in new_digest_obj.inputs:
            if i in self:
                # Input is already in the dag
                self.dependents[i].add(new_digest_obj)

            else:
                # Input is not in the dag yet, mark it so we can later update
                # the dependencies properly if it is later added to the dag.

                i_edge_deps = self._dependents_just_beyond_edge.setdefault(i,set())
                i_edge_deps.add(new_digest_obj)


    def _swap(self,old_digest_obj,new_digest_obj):
        assert old_digest_obj.digest in self._digests

        # If we're being asked to replace an object with one whose inputs are
        # not a strict superset, something is quite wrong.
        assert set(old_digest_obj.inputs).issubset(set(new_digest_obj.inputs))

        self._digests[old_digest_obj.digest] = new_digest_obj
        self.__link_inputs(new_digest_obj)


    def _add(self,new_digest_obj):
        assert new_digest_obj.digest not in self._digests
        self._digests[new_digest_obj.digest] = new_digest_obj

        assert new_digest_obj not in self.dependents
        self.dependents[new_digest_obj] = set()

        # Update other digests .inputs to point to the new object
        dependents = self._dependents_just_beyond_edge.get(new_digest_obj,None)
        if dependents is not None:
            for dependent in dependents:
                dependent._swap_input_obj(new_digest_obj)
            self._dependents_just_beyond_edge.pop(new_digest_obj)


        # Add dependencies for the new digest's inputs
        self.__link_inputs(new_digest_obj)


    def digests(self):
        return self._digests.iterkeys()
