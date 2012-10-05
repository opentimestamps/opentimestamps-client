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

# Operations - edges in DAG
# Digests - vertexes in DAG

class __MasterOpSerializer(serialization.Serializer):
    instantiator = None

    @classmethod
    def __create_arguments_dict(cls,obj):
        r = {}
        for arg_name in obj.__class__.op_arguments:
            try:
                r[arg_name] = getattr(obj,arg_name)
            except AttributeError:
                raise AttributeError("Missing attribute '%s' from %r instance" %\
                        (arg_name,obj.__class__))

        # inputs are handled specially. Rather than serializing the actual Op
        # objects themselves, serialize the object's digests instead.
        r['inputs'] = tuple(i.digest for i in obj.inputs)

        return r

    @classmethod
    def json_serialize(cls,obj):
        arg_dict = cls.__create_arguments_dict(obj)
        return {obj.__class__.op_name:
                    serialization.DictSerializer.json_serialize(arg_dict)}

    @classmethod
    def json_deserialize(cls,json_obj):
        args_dict = serialization.DictSerializer.json_deserialize(json_obj,do_typed_object_hack=False)
        return cls.instantiator(**args_dict)

    @classmethod
    def _binary_serialize(cls,obj,fd):
        args_dict = cls.__create_arguments_dict(obj)
        serialization.DictSerializer._binary_serialize(args_dict,fd)

    @classmethod
    def _binary_deserialize(cls,fd):
        args_dict = serialization.DictSerializer._binary_deserialize(fd)
        return cls.instantiator(**args_dict)

def register_Op(cls):
    # We don't support multiple inheritence for ops. If we did the following
    # code would need to be changed. Probably better to avoid having to use
    # multiple inheritence, as if we switch to Cython later the resulting
    # compiled code is a lot faster.
    assert len(cls.__bases__) == 1

    # Process the op arguments, adding arguments from base classes. 

    all_args = {}

    # Inherit arguments from the base class
    if issubclass(cls.__base__,Op):
        all_args.update(cls.__base__.op_arguments)

    for arg_name in cls.op_arguments:
        if arg_name in all_args: 
            raise ValueError(\
"Argument name '%s' defined in %r has the same name as an argument in base class %r" %\
                    (arg_name,cls,all_args[arg_name]))
        else:
            all_args[arg_name] = cls

    cls.op_arguments = all_args

    # Create a serialization class for the Op class to allow it to be
    # serialized.
    class new_op_serializer(__MasterOpSerializer):
        type_name = cls.op_name
        typecode_byte = serialization.typecodes_by_name[type_name]
        auto_serialized_classes = (cls,)
        instantiator = cls

    # Change the name to something meaningful. Otherwise they'll all have the
    # name 'new_op_serializer'; not very useful for debugging.
    new_op_serializer.__name__ = '%sType' % cls.op_name

    serialization.register_serializer(new_op_serializer)

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

    def __init__(self,inputs=(),digest=None,dag=None,**kwargs):
        self.__dict__.update(kwargs)

        self.dag = dag

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

    def __init__(self,digest=None,inputs=(),dag=None):
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

        super(Digest,self).__init__(digest=digest,inputs=inputs,dag=dag)



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

# The regex that valid notary method names must match.
#
# Basically, first character must be alphabetical. Second character must exist
# and may also have numbers or the characters _ - or .
#
# Unicode characters are not allowed.
valid_notary_method_name_regex = '^[A-Za-z][A-Za-z0-9_\-\.]+$'
valid_notary_method_name_re = re.compile(valid_notary_method_name_regex)

@register_Op
class Verify(Op):
    op_name = 'Verify'
    op_arguments =\
            ('timestamp',
             'notary_method',
             'notary_method_version',
             'notary_identity',
             'notary_args')

    # These arguments are used to computer the digest
    hashed_arguments = ('inputs','timestamp',
                        'notary_method','notary_method_version',
                        'notary_identity','notary_args')

    def __init__(self,inputs=(),
            timestamp=None,
            notary_method=None,
            notary_method_version=0,
            notary_identity=u'',
            notary_args={},
            **kwargs):

        if len(inputs) != 1:
            raise ValueError('Verify operations must have exactly one input, got %d' % len(inputs))

        if timestamp is None:
            timestamp = time_to_timestamp(time.time())

        if not (isinstance(timestamp,int) or isinstance(timestamp,long)):
            raise TypeError("Timestamp must be an integer")
        elif timestamp < 0:
            raise ValueError("Timestamp must be a positive integer")

        # Note that creating a timestamp in the past is not an error to allow
        # the import of timestamps from other timestamping systems.

        if notary_method is None:
            raise ValueError("notary_method not specified")
        elif re.match(valid_notary_method_name_re,notary_method) is None:
            raise ValueError("notary_method must match the regex '%s', got %r" %
                    (valid_notary_method_name_regex,notary_method))

        if not isinstance(notary_method_version,int):
            raise TypeError("notary_method_version must be an integer")
        elif notary_method_version < 0:
            raise ValueError("notary_method_version must be >= 0")

        self.timestamp = int(timestamp)
        self.notary_method = unicode(notary_method)
        self.notary_method_version = int(notary_method_version)
        self.notary_identity = unicode(notary_identity)
        self.notary_args = notary_args

        super(Verify,self).__init__(inputs=inputs,**kwargs)


    def calculate_digest(self):
        digest_dict = {}
        for hashed_key in self.hashed_arguments:
            digest_dict[hashed_key] = getattr(self,hashed_key)
        return serialization.DictSerializer.binary_serialize(digest_dict)

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


    def path(self,starts,dests):
        raise NotImplementedError



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
