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


"""Serialization and deserialization

We provide the ability to serialize to JSON-compatible objects, as well as a
custom binary format. Critically for hashing, the custom binary format is
guaranteed to always produce the same binary bytes for the same encoded data,
even after multiple round-trips.

The follwing basic types are supported:

    null  - JSON null, Python None
    bool  - True or False
    int   - Signed integer, can be arbitrarily large.
    str   - Unicode string, NFC normalized, the null character is not allowed.
    bytes - Binary bytes
    list  - Ordered list
    dict  - JSON key:value map. As in JSON, the keys must be strings.
    obj   - See 'Typed Objects' below

Floating point numbers are not supported to avoid the potential problem of
different representations.

Typed Objects
-------------

Arbitrary Python objects are supported. See the ObjectSerializer class for
information on how to use this.


Type Names
----------

For each type that can be serialized has a type name.

In the official OpenTimestamps software all type names are either single words,
or start with the string 'ots' If you want to make your own extensions, please
use a prefix to prevent clashes. Using a UUID, as shown above, is a good idea.
Another method is to use a domain name that you control: thefoocompany.com.Foo

See Serializer.type_name_regex for what characters are allowed in a
type name.


JSON Representation
-------------------

Most of the basic Python objects can be represented in JSON directly. Bytes are
hex-encoded and stored in strings, with a special prefix to disambiguate. See
StrSerializer/BytesSerializer for details.

Type information is added with a special {'type_name':<json serialized value>}
syntax; see JSONTypedSerializer for details.


Binary Representation
---------------------

The 'basic' types each have single byte typecodes, defined in the
typecodes_by_typename dictionary. The line format is:

    <typecode> <binary serialization of the value>

Each binary has its own way of serializing the value. The typecode is
responsible for finding the end of the serialized value; there isn't a generic
length mechanism. We do not use struct anywhere for serialization. Every binary
serialization in turn uses other types defined here. This strategy was chosen
to make life easier for anyone trying to re-implement the serialization in a
different language.

The serialization is designed to be easy to implement first. Thus we only
support variable length integers, not the usual plethora of fixed-length types.
Some aspects, particularly storing key names directly, may appear wasteful, but
it is assumed that zlib compression will be applied to the output. Therefor
don't try to keep key names and similar things short.

That said version two of the serialization will implement a digest output
re-use mechanism so we don't have to store every intermediate digest
calculated.


Bitfields
---------

Note that if you want to use bitfields for your type they work just fine with
variable length integers if you're using a decent big integer implementation
like Pythons:

>>> a = 0b101
>>> a & 0b1000
0

Keep in mind that the bits most likely to be set to 1 should be stored in the
least significant positions.


Extending the serialization mechanism
-------------------------------------

Feel free to add your own types with the ObjectSerializer subclasses.
Implementations that do not know what your types are will still round-trip the
data without loss.

However implementing new basic types, that is, with the Serializer subclasses
that define new typecodes, is not supported and is considered a major version
change.
"""

json_major_version = 0
json_minor_version = 0

binary_major_version = 0
binary_minor_version = 0


import unicodedata
import binascii
import types
import re

class SerializationError(Exception):
    pass

class SerializationUnknownTypeError(SerializationError):
    pass

class SerializationUnknownTypeCodeError(SerializationError):
    pass

class SerializationTypeNameInvalidError(SerializationError):
    pass


# Note that typecodes all have the highest bit unset. This is so they don't look
# like variable-length integers, hopefully causing a vint parser to quit
# earlier rather than later.
#
# 0x00 to 0x1F for typecodes is a good choice as they're all unprintable.
typecodes_by_typename = \
    {'null'      :b'\x00',
    'bool'      :b'\x01',
    'int'       :b'\x02',
    'uint'      :b'\x03',
    'str'       :b'\x04',
    'bytes'     :b'\x05',
    'dict'      :b'\x06',
    'list'      :b'\x07',
    'list_end'  :b'\x08',
    'obj'       :b'\t',} # also == b'\x09'

serializers_by_typecode_byte = {}
serializers_by_type_name = {}

auto_serializers_by_class = {}
auto_json_deserializers_by_class = {}

def register_serializer(cls):
    """Decorator to register a Serializer

    Use this with every Serializer class you make.
    """
    cls.type_name = str(cls.type_name)
    cls.validate_type_name()
    for auto_cls in cls.auto_serialized_classes:
        auto_serializers_by_class[auto_cls] = cls

    for auto_json_cls in cls.auto_json_deserialized_classes:
        auto_json_deserializers_by_class[auto_json_cls] = cls

    # ObjectSerializer is a special case, as it maps to many different
    # classes. Bit ugly though, as we have to handle the fact that it's also a
    # forward declaration.
    try:
        if not issubclass(cls,SerializedObjectSerializer) or cls is SerializedObjectSerializer:
            serializers_by_typecode_byte[cls.typecode_byte] = cls
    except NameError:
        serializers_by_typecode_byte[cls.typecode_byte] = cls

    serializers_by_type_name[cls.type_name] = cls

    return cls



class Serializer(object):
    """Serialize/deserialize methods for a class

    Generally you won't use these classes directly to actually serialize and
    deserialize objects. Rather you create subclasses of these classes to
    implement your own serialization scheme.
    """

    type_name = None
    typecode_byte = None

    # The list of classes that are automatically serialized using this
    # serialization class. That is, (json|binary)_serialize() will check that
    # obj.__class__ is auto_class, and if so, use this serialization method.
    auto_serialized_classes = ()

    # The list of JSON classes that are automatically deserialized using this
    # serialization class. That is, json_deserialize() will check that
    # json_obj.__class__ is cls, and if so, use this deserialization method.
    auto_json_deserialized_classes = ()

    type_name_regex = '^[A-Za-z0-9\-\_\.]+$'
    type_name_re = re.compile(type_name_regex)

    @classmethod
    def validate_type_name(cls,name=None):
        if name is None:
            name = cls.type_name

        if not isinstance(name,str):
            raise SerializationTypeNameInvalidError('Type name must be unicode string; got type %r' % name.__class__)

        if not re.match(cls.type_name_re,name):
            raise SerializationTypeNameInvalidError(
                    "Invalid type name '%s'; names must match regex '%s'" % (name,cls.type_name_regex))


    @classmethod
    def json_serialize(cls,obj):
        """Serialize obj to a JSON-compatible object

        This function assumes that obj is of the correct type.
        """
        # Default behavior for native JSON objects.
        return obj


    @classmethod
    def json_deserialize(cls,json_obj):
        """Deserialize json_obj from a JSON-compatible object

        This function assumes that json_obj is of the correct type.
        """
        # Default behavior for native JSON objects.
        return json_obj


    @classmethod
    def _binary_serialize(cls,obj,fd):
        """Actual binary_serialize() implementation.

        Type-specific code goes here. You don't need to include the typecode
        byte, Serializer.binary_serialize() does that for you.
        """
        raise NotImplementedError("Don't use the Serializer class directly")


    @classmethod
    def binary_serialize(cls,obj,fd=None):
        """Serialize obj to the binary format

        This function assumes obj is of the correct type.

        The serialized bytes are written using fd.write(); generally fd will be
        a file descriptor. There is no return value.

        As a convenience for debugging and similar activities, if fd is not set
        this function returns bytes instead.
        """
        our_fd = fd
        if our_fd is None:
            import io
            our_fd = io.BytesIO()

        # Write the typecode byte.
        our_fd.write(cls.typecode_byte)

        cls._binary_serialize(obj,our_fd)

        if fd is None:
            our_fd.seek(0)
            r = our_fd.read()
            our_fd.close()
            return r


    @classmethod
    def _binary_deserialize(cls,fd):
        """Actual binary_deserialize() implementation.

        Type-specific code goes here. You don't need to include the typecode
        byte, Serializer.binary_deserialize() does that for you.
        """
        raise NotImplementedError("Don't use the Serializer class directly")


    @classmethod
    def binary_deserialize(cls,fd):
        """Deserialize obj from the binary format

        This function assumes the typecode byte has already been read from fd
        by the module-level binary_serialize(). Generally you would use that,
        rather than these functions directly.

        The serialized bytes are read using fd.read(); generally fd will be
        a file descriptor.

        As a convenience for debugging and similar activities, fd can also be
        bytes rather than a file descriptor.
        """
        if isinstance(fd,bytes):
            import io
            with io.BytesIO(fd) as fd:
                return cls._binary_deserialize(fd)
        else:
            return cls._binary_deserialize(fd)



def get_serializer_for_obj(obj):
    """Returns the serializer we should use to (de)serialize obj

    Tries the exact match to obj.__class__ first, and also does some
    duck-typing.

    Returns (cls,new_obj)
    """
    try:
        return (auto_serializers_by_class[obj.__class__],obj)
    except KeyError:
        # Can we iterate obj?
        #
        # This covers generators, iterators, sets etc.
        cls = None
        try:
            return (ListSerializer,iter(obj))
        except TypeError:
            # Any other duck-types we should do?
            raise TypeError("Don't know how to serialize objects of type %r" % obj.__class__)


def json_serialize(obj):
    """Serialize obj to a JSON-compatible object"""
    (cls,obj) = get_serializer_for_obj(obj)
    return cls.json_serialize(obj)


def json_deserialize(json_obj):
    """Deserialize json_obj from a JSON-compatible object"""
    try:
        cls = auto_json_deserializers_by_class[json_obj.__class__]
    except KeyError:
        raise SerializationError("Can't json_deserialize() non-JSON class %r" % json_obj.__class__)

    return cls.json_deserialize(json_obj)


def binary_serialize(obj,fd=None):
    """Serialize obj to the binary format

    The serialized bytes are written using fd.write(); generally fd will be
    a file descriptor. There is no return value.

    As a convenience for debugging and similar activities, if fd is not set
    this function returns bytes instead.
    """
    if fd is None:
        import io
        with io.BytesIO() as fd:
            binary_serialize(obj,fd)
            fd.seek(0)
            return fd.read()
    else:
        (cls,obj) = get_serializer_for_obj(obj)
        cls.binary_serialize(obj,fd)


def binary_deserialize(fd):
    """Deserialize obj from the binary format

    This function assumes the typecode byte has already been read from fd
    by the module-level binary_serialize(). Generally you would use that,
    rather than these functions directly.

    The serialized bytes are read using fd.read(); generally fd will be
    a file descriptor.

    As a convenience for debugging and similar activities, fd can also be
    bytes rather than a file descriptor.
    """
    if isinstance(fd,bytes):
        import io
        with io.BytesIO(fd) as fd:
            return binary_deserialize(fd)
    else:
        typecode_byte = fd.read(1)

        try:
            cls = serializers_by_typecode_byte[typecode_byte]
        except KeyError:
            raise SerializationUnknownTypeCodeError('Unknown typecode %r' % typecode_byte)

        return cls.binary_deserialize(fd)



@register_serializer
class NullSerializer(Serializer):
    type_name = 'null'
    typecode_byte = typecodes_by_typename[type_name]
    auto_serialized_classes = (type(None),)
    auto_json_deserialized_classes = (type(None),)

    # Since there is only one None value, we don't actually have to do
    # anything.
    @classmethod
    def _binary_serialize(cls,obj,fd):
        pass

    @classmethod
    def _binary_deserialize(cls,fd):
        pass



@register_serializer
class BoolSerializer(Serializer):
    type_name = 'bool'
    typecode_byte = typecodes_by_typename[type_name]
    auto_serialized_classes = (bool,)
    auto_json_deserialized_classes = (bool,)

    # Since there is only one None value, we don't actually have to do
    # anything.
    @classmethod
    def _binary_serialize(cls,obj,fd):
        if obj:
            fd.write(b'\xff')
        else:
            fd.write(b'\x00')

    @classmethod
    def _binary_deserialize(cls,fd):
        c = fd.read(1)
        if c == b'\xff':
            return True
        elif c == b'\x00':
            return False
        else:
            raise SerializationError("Got %r while binary deserializing a bool; expected '\\xff' or '\\x00'" % c)



@register_serializer
class UIntSerializer(Serializer):
    """Unsigned variable length integer.

    This Serializer isn't used automatically, rather it exists so that other
    serializers have a convenient way of serializing unsigned ints for internal
    use.
    """
    type_name = 'uint'
    typecode_byte = typecodes_by_typename[type_name]

    @classmethod
    def _binary_serialize(cls,obj,fd):
        while obj >= 0b10000000:
            fd.write(bytes([(obj & 0b01111111) | 0b10000000]))
            obj = obj >> 7
        fd.write(bytes([(obj & 0b01111111) | 0b00000000]))

    @classmethod
    def _binary_deserialize(cls,fd):
        r = 0
        i = 0

        while True:
            next_word = ord(fd.read(1))
            r |= (next_word & 0b01111111) << i

            i += 7
            if not next_word & 0b10000000:
                break
        return r



@register_serializer
class IntSerializer(Serializer):
    """Signed variable length integer.

    Uses the same varint+zigzag encoding as in Google Protocol Buffers for the
    binary format. No encoding required in the JSON version.
    """
    type_name = 'int'
    typecode_byte = typecodes_by_typename[type_name]
    auto_serialized_classes = (int,int)
    auto_json_deserialized_classes = (int,int)

    # FIXME: we should handle integers larger than what JavaScript can support
    # by using the JSON typed object hack and converting them to strings.

    @classmethod
    def _binary_serialize(cls,obj,fd):
        # zig-zag encode
        if obj >= 0:
            obj = obj << 1
        else:
            obj = (obj << 1) ^ (~0)

        UIntSerializer._binary_serialize(obj,fd)

    @classmethod
    def _binary_deserialize(cls,fd):
        i = UIntSerializer._binary_deserialize(fd)

        # zig-zag decode
        if i & 0b1:
            i ^= ~0
        return i >> 1



@register_serializer
class BytesSerializer(Serializer):
    type_name = 'bytes'
    typecode_byte = typecodes_by_typename[type_name]
    auto_serialized_classes = (bytes,str)
    auto_json_deserialized_classes = ()

    @classmethod
    def json_serialize(cls,obj):
        return '#' + str(binascii.hexlify(obj),'utf8')

    @classmethod
    def json_deserialize(cls,json_obj):
        assert json_obj[0] == '#'
        return binascii.unhexlify(bytes(json_obj[1:],'utf8'))

    @classmethod
    def _binary_serialize(cls,obj,fd):
        UIntSerializer._binary_serialize(len(obj),fd)
        fd.write(obj)

    @classmethod
    def _binary_deserialize(cls,fd):
        l = UIntSerializer._binary_deserialize(fd)
        return fd.read(l)



@register_serializer
class StrSerializer(Serializer):
    type_name = 'str'
    typecode_byte = typecodes_by_typename[type_name]
    auto_serialized_classes = (str,)
    auto_json_deserialized_classes = (str,)

    @classmethod
    def __utf8_normalize(cls,obj):
        # Ban nulls to make life easier for implementers, particularly C/C++
        # versions.
        if '\u0000' in obj:
            raise ValueError("Strings must not have null characters in them to be serialized.")

        # NFC normalization is shortest. We don't care about legacy characters;
        # we just want strings to always normalize to the exact same bytes so
        # that we can get consistent digests.
        return unicodedata.normalize('NFC',obj)

    @classmethod
    def json_serialize(cls,obj):
        obj = cls.__utf8_normalize(obj)

        if len(obj) > 0:
            if obj[0] == '#':
                obj = '\\' + obj
            elif obj[0] == '\\':
                obj = '\\' + obj
        return obj

    @classmethod
    def json_deserialize(cls,json_obj):
        if len(json_obj) > 0 and json_obj[0] == '#':
            # This is actually bytes, let the bytes serializer handle it.
            return BytesSerializer.json_deserialize(json_obj)
        elif len(json_obj) > 0 and json_obj[0] == '\\':
            # Something got escaped.
            return json_obj[1:]
        else:
            return json_obj

    @classmethod
    def _binary_serialize(cls,obj,fd):
        obj = cls.__utf8_normalize(obj)
        obj_utf8 = obj.encode('utf8')

        BytesSerializer._binary_serialize(obj_utf8,fd)

    @classmethod
    def _binary_deserialize(cls,fd):
        obj_utf8 = BytesSerializer._binary_deserialize(fd)
        return obj_utf8.decode('utf8')

import functools
@functools.total_ordering
class Digestible(object):
    """Base class for objects with digests

    Digestible objects are equality tested, ordered, and hashed based on their
    digest attribute. The digest is calculated from the attributes in
    all_digested_attributes. Any attempt to set or delete an attribute in that
    list after the digest has been calculated will fail.

    Digests are always bytes instances, no sub-classes are allowed.

    Use with the digestible_object_subclass decorator to setup
    all_digested_attributes properly, including all base classes.
    """

    __locked = False
    digest = None
    digested_attributes = frozenset()
    all_digested_attributes = frozenset()

    @property
    def locked(self):
        """True if the instance is locked"""
        return self.__locked

    def calculate_digest(self):
        """Calculate and return the digest

        This method must alway calculate the digest from scratch each time.

        The default implementation is to take the values of each attribute (with getattr) in
        .digested_attributes, add them to a dict, and binary serialize that
        dict and the object's serialization type name. Missing attributes are
        ignored.

        As a special case, values that are isinstance(Digestible) use the
        value's digest attribute instead of the value.
        """
        d = {}
        for attr in self.all_digested_attributes:
            try:
                value = getattr(self,attr)
            except AttributeError:
                continue

            if isinstance(value,Digestible):
                if not value.__locked:
                    raise ValueError("Can't calculate digest; attribute %s not locked." % attr)
                value = value.digest
            d[attr] = value

        d = {auto_serializers_by_class[self.__class__].type_name:d}

        return binary_serialize(d)



    def lock(self):
        """Lock the instance from any changes that would change the digest

        The digest attribute is calculated and saved by lock()
        """
        new_digest = self.calculate_digest()
        if not new_digest.__class__ is bytes:
            raise TypeError('digest must be bytes; got %r instance instead.' % new_digest.__class__)

        super().__setattr__('digest',new_digest)
        self.__locked = True
        self.__digest_hash = hash(self.digest)


    def __setattr__(self,name,value):
        if name == 'digest':
            raise AttributeError("Can't set digest attribute of a Digestible instance directly.")
        elif self.__locked and name in self.all_digested_attributes:
            raise AttributeError("Can't set attribute; used to calculate digest and %s instance is locked." % type(self))
        super(Digestible,self).__setattr__(name,value)

    def __delattr__(self,name):
        if name == 'digest':
            raise AttributeError("Can't delete digest attribute from a Digestible instance.")
        elif self.__locked and name in self.all_digested_attributes:
            raise AttributeError("Can't delete attribute; used to calculate digest and %s instance is locked." % type(self))
        super(Digestible,self).__delattr__(name)

    def __eq__(self,other):
        if not isinstance(other,Digestible):
            # If we don't allow unlocked == <other type>, the order of the
            # operands in == would change whether the test was allowed or not!
            return False
        else:
            if not self.__locked or not other.__locked:
                raise ValueError('Digestible objects can not be tested for equality until they are locked.')
            else:
                return self.digest == other.digest

    def __lt__(self,other):
        if not isinstance(other,Digestible):
            return NotImplemented
        else:
            if not self.__locked or not other.__locked:
                raise ValueError('Digestible objects are unordered until they are locked.')
            else:
                return self.digest < other.digest


    def __hash__(self):
        if not self.__locked:
            raise ValueError('Digestible objects can not be hashed until they are locked')
        return self.__digest_hash


def digestible_object_subclass():
    """Decorator to set all_digested_attributes, including from base classes"""
    def f(cls):
        if not 'digested_attributes' in cls.__dict__:
            cls.digested_attributes = ()
        cls.digested_attributes = frozenset(cls.digested_attributes)

        # Get the set of all digested attributes
        def walk(cls,all_attrs,defining_classes):
            defining_classes = defining_classes.copy()
            try:
                attrs = cls.digested_attributes
            except AttributeError:
                pass
            else:
                for attr in cls.digested_attributes:
                    if attr in defining_classes:
                        raise AttributeError(\
"Digested attribute '{}' already defined by base class {}; conflicts with definition in subclass {}"\
.format(attr,defining_classes[attr],cls))
                    else:
                        defining_classes[attr] = cls

                    all_attrs.add(attr)

            for base_cls in cls.__bases__:
                if issubclass(base_cls,SerializedObject):
                    walk(base_cls,all_attrs,defining_classes)
                else:
                    continue

        all_attrs = set()
        walk(cls,all_attrs,{})
        cls.all_digested_attributes = frozenset(all_attrs)

        return cls

    return f

class SerializedObject:
    """Serialization support for objects

    Make your class a subclass of this class, and use the
    serialized_object_subclass decorator.

    On de-serialization your __init__() method is called with those attributes
    as keyword arguments. Unknown attributes that were deserialized, but are
    not in serialized_attributes, will not be in kwargs, but they will be saved
    to be re-serialized later.

    Unknown types of objects are also handled gracefully, and will wind up as
    plain SerializedObject instances and can be re-serialized losslessly.
    """

    # These attributes will be serialized. It is an error to set an attribute
    # here that is already set by a base class.
    serialized_attributes = frozenset()

    # This will be set to the union of every serialized_attribute defined in
    # your class and all base classes by the simple_serialized_object
    # decorator.
    all_serialized_attributes = frozenset()

    def get_dict_to_serialize(self):
        """Return the dict to be serialized.

        Default behavior is for every attribute in serialized_attributes to be
        extracted from the instance __dict__, and any unknown attributes added
        in. Override this if requird.

        For forward compatibility missing attributes are ignored.
        """

        r = {}
        for name in self.all_serialized_attributes:
            try:
                r[name] = self.__dict__[name]
            except KeyError:
                pass
        try:
            r.update(self._SerializedObject_unknown_attributes)
        except AttributeError:
            pass

        return r

    def __init__(self,**kwargs):
        """Initialize

        All keys in the keyword arguments will be setattr'd to self.
        """
        for name,value in kwargs.items():
            setattr(self,name,value)


@register_serializer
class SerializedObjectSerializer(Serializer):
    """The serialization method for SerializedObject subclasses"""
    type_name = 'obj'
    typecode_byte = typecodes_by_typename[type_name]
    auto_serialized_classes = (SerializedObject,)
    auto_json_deserialized_classes = ()

    serialized_class = SerializedObject

    @classmethod
    def get_type_name(cls,obj):
        """Return the type name for the object instance

        You need to change this; default is for unknown objects.
        """
        return obj._SerializedObjectSerializer_type_name

    @classmethod
    def create_kwargs(cls,args_dict):
        kwargs = {}
        for name in cls.serialized_class.all_serialized_attributes:
            try:
                kwargs[name] = args_dict.pop(name)
            except KeyError:
                pass
        kwargs['_SerializedObject_unknown_attributes'] = args_dict

        return kwargs

    @classmethod
    def json_serialize(cls,obj):
        dict_to_serialize = obj.get_dict_to_serialize()
        return {cls.get_type_name(obj):
                    DictSerializer.json_serialize(dict_to_serialize,do_typed_object_hack=False)}

    @classmethod
    def json_deserialize(cls,json_obj,type_name=None):
        if type_name is None:
            type_name = cls.type_name
        cls.validate_type_name(type_name)
        args_dict = DictSerializer.json_deserialize(json_obj,do_typed_object_hack=False)
        kwargs = cls.create_kwargs(args_dict)
        return cls.serialized_class(_SerializedObjectSerializer_type_name=type_name,**kwargs)

    @classmethod
    def _binary_serialize(cls,obj,fd):
        StrSerializer._binary_serialize(cls.get_type_name(obj),fd)
        dict_to_serialize = obj.get_dict_to_serialize()
        DictSerializer._binary_serialize(dict_to_serialize,fd)

    @classmethod
    def _binary_deserialize(cls,fd):
        type_name = StrSerializer._binary_deserialize(fd)
        cls.validate_type_name(type_name)
        args_dict = DictSerializer._binary_deserialize(fd)

        try:
            cls = serializers_by_type_name[type_name]
        except KeyError:
            cls = SerializedObjectSerializer

        kwargs = cls.create_kwargs(args_dict)
        return cls.serialized_class(_SerializedObjectSerializer_type_name=type_name,**kwargs)


def serialized_object_subclass(type_name_prefix,type_name=None):
    """Decorator to use with SerializedObjects subclasses

    The type name will be set to type_name_prefix + '.' + cls.__name__
    """
    def f(cls):
        if not 'serialized_attributes' in cls.__dict__:
            cls.serialized_attributes = ()
        cls.serialized_attributes = frozenset(cls.serialized_attributes)

        # Get the set of all serialized attributes
        def walk(cls,all_attrs,defining_classes):
            defining_classes = defining_classes.copy()
            for attr in cls.serialized_attributes:
                if attr in defining_classes:
                    raise AttributeError(\
"Serialized attribute '{}' already defined by base class {}; conflicts with definition in subclass {}"\
.format(attr,defining_classes[attr],cls))
                else:
                    defining_classes[attr] = cls

                all_attrs.add(attr)

            for base_cls in cls.__bases__:
                if issubclass(base_cls,SerializedObject):
                    walk(base_cls,all_attrs,defining_classes)
                else:
                    continue

        all_attrs = set()
        walk(cls,all_attrs,{})
        cls.all_serialized_attributes = frozenset(all_attrs)

        nonlocal type_name
        if type_name is None:
            type_name = type_name_prefix + '.' + cls.__name__

        class new_serializer(SerializedObjectSerializer):
            @classmethod
            def get_type_name(serializer_cls,obj):
                return type_name

            get_dict_to_serialize = cls.get_dict_to_serialize 
            auto_serialized_classes = (cls,)
            serialized_class = cls

        new_serializer.type_name = type_name

        # Set a sane name.
        new_serializer.__name__ = '_%sSerializer' % cls.__name__

        # Module should be the module the class was defined in, not here.
        new_serializer.__module__ = cls.__module__

        register_serializer(new_serializer)

        return cls
    return f


class DigestibleSerializedObject(SerializedObject,Digestible):
    """A serialized object that is digestible"""
    serialized_attributes = frozenset()
    def __init__(self,digest=None,**kwargs):
        super().__init__(**kwargs)

def digestible_serialized_object_subclass(*args,**kwargs):
    """Decorator to use with DigestibleSerializedObjects subclasses

    Applies both the appropriate decorators.
    """
    def f(cls):
        cls = serialized_object_subclass(*args,**kwargs)(cls)
        cls = digestible_object_subclass()(cls)
        return cls
    return f


class JsonTypedObjectSerializer(Serializer):
    """Typed object representation for JSON

    Basically we need a uniform way to add types to JSON. So we overload the
    dict type as follows:

    {"type_name":<JSON serialization>}

    and the dict serialization code recognizes that special form and calls us.
    Not relevant for the binary serialization, as that has types already,
    either in a basic type or with the above ObjectSerializer
    """
    type_name = None
    typecode_byte = None
    auto_serialized_classes = ()
    auto_json_deserialized_classes = ()

    @classmethod
    def json_deserialize(cls,json_obj):
        keys = list(json_obj.keys())
        assert len(keys) == 1
        type_name = keys[0]

        cls.validate_type_name(type_name)

        try:
            serializer_cls = serializers_by_type_name[type_name]
        except KeyError:
            serializer_cls = SerializedObjectSerializer

        if serializer_cls is DictSerializer:
            # Don't apply the hack recursively.
            return serializer_cls.json_deserialize(json_obj[type_name],do_typed_object_hack=False)
        elif serializer_cls is SerializedObjectSerializer:
            return serializer_cls.json_deserialize(json_obj[type_name],type_name=type_name)
        else:
            return serializer_cls.json_deserialize(json_obj[type_name])

    @classmethod
    def json_serialize(cls,obj):
        (serializer_cls,obj) = get_serializer_for_obj(obj)
        return {serializer_cls.type_name:json_serialize(obj)}

    # Makes no sense to use these as ObjectSerializer doesn't have a valid
    # typecode_byte.
    @classmethod
    def _binary_serialize(cls,obj,fd):
        assert False

    @classmethod
    def _binary_deserialize(cls,fd):
        assert False



@register_serializer
class DictSerializer(Serializer):
    type_name = 'dict'
    typecode_byte = typecodes_by_typename[type_name]
    auto_serialized_classes = (dict,)
    auto_json_deserialized_classes = (dict,)

    @classmethod
    def __check_key(cls,key):
        if not isinstance(key,str) and not isinstance(key,str):
            raise SerializationError("Can't serialize dicts with non-string keys; got %r" % key)
        elif len(key) < 1:
            raise SerializationError("Can't serialize dicts with empty keys")

    @classmethod
    def json_serialize(cls,obj,do_typed_object_hack=True):
        json_obj = {}

        for key,value in list(obj.items()):
            cls.__check_key(key)
            json_obj[key] = json_serialize(value)

        if len(list(json_obj.keys())) == 1 and do_typed_object_hack:
            # Hack! Serialize with a typed object wrapper, because otherwise
            # we'll trigger the typed object code.
            json_obj = {'dict':json_obj}
        return json_obj

    @classmethod
    def json_deserialize(cls,json_obj,do_typed_object_hack=True):
        if len(list(json_obj.keys())) == 1 and do_typed_object_hack:
            # Hack! This looks like a typed object, so send it to the JSON
            # typed object deserializer.
            return JsonTypedObjectSerializer.json_deserialize(json_obj)

        obj = {}

        for key,value in list(json_obj.items()):
            obj[key] = json_deserialize(value)
        return obj

    @classmethod
    def _binary_serialize(cls,obj,fd):
        for key in sorted(obj.keys()):
            value = obj[key]
            cls.__check_key(key)
            key = str(key)
            StrSerializer._binary_serialize(key,fd)

            binary_serialize(value,fd)

        # empty key signals the end
        StrSerializer._binary_serialize('',fd)

    @classmethod
    def _binary_deserialize(cls,fd):
        obj = {}
        while True:
            key = StrSerializer._binary_deserialize(fd)
            if len(key) < 1:
                break

            value = binary_deserialize(fd)

            obj[key] = value
        return obj



# Signals the end of a list.
class _ListEndMarker(object):
    pass
_list_end_marker = _ListEndMarker()

@register_serializer
class _ListEndMarkerSerializer(Serializer):
    type_name = 'list_end'
    typecode_byte = typecodes_by_typename[type_name]
    auto_serialized_classes = (_ListEndMarker,)
    auto_json_deserialized_classes = ()

    @classmethod
    def json_serialize(cls,obj):
        raise AssertionError("ListEndMarker objects are for internal use only")

    @classmethod
    def json_deserialize(cls,json_obj):
        raise AssertionError("ListEndMarker objects are for internal use only")

    @classmethod
    def _binary_serialize(cls,obj,fd):
        pass

    @classmethod
    def _binary_deserialize(cls,fd):
        return _list_end_marker



@register_serializer
class ListSerializer(Serializer):
    type_name = 'list'
    typecode_byte = typecodes_by_typename[type_name]
    auto_serialized_classes = (list,tuple,types.GeneratorType)
    auto_json_deserialized_classes = (list,tuple)

    @classmethod
    def json_serialize(cls,obj):
        return [json_serialize(o) for o in obj]

    @classmethod
    def json_deserialize(cls,json_obj):
        return [json_deserialize(o) for o in json_obj]

    @classmethod
    def _binary_serialize(cls,obj,fd):
        for o in obj:
            binary_serialize(o,fd)
        binary_serialize(_list_end_marker,fd)

    @classmethod
    def _binary_deserialize(cls,fd):
        obj = []
        while True:
            obj.append(binary_deserialize(fd))
            if obj[-1] is _list_end_marker:
                obj.pop()
                return obj
