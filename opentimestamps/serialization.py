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


# Goal: we need to be able to extend JSON with type information, while at the
# same time being able to deterministicly create a binary serialization of the
# information going into the JSON.

# name.type.subtype : value with type being optional if default json
# interpretation is correct, subtype useful for lists. Lists with multiple
# types in them aren't supported.

import cStringIO
import unicodedata
import binascii
import types

class SerializationError(StandardError):
    pass

# Note that typecodes all have the highest bit unset. This is so they don't look
# like variable-length integers, hopefully causing a vint parser to quit
# earlier rather than later.
#
# 0x00 to 0x1F for typecodes is a good choice as they're all unprintable.
typecodes_by_name = {'null'      :b'\x00',
                     'bool'      :b'\x01',
                     'int'       :b'\x02',
                     'uint'      :b'\x03',
                     'str'       :b'\x04',
                     'bytes'     :b'\x05',
                     'dict'      :b'\x06',
                     'list'      :b'\x07',
                     'list_end'  :b'\x08',

                     'Op'        :b'\x10',
                     'Digest'    :b'\x11',
                     'Hash'      :b'\x12',
                     'Verify'    :b'\x13',}

serializers_by_typecode_byte = {}
serializers_by_type_name = {}

auto_serializers_by_class = {}
auto_json_deserializers_by_class = {}

def register_serializer(cls):
    """Decorator to register a Serializer

    Use this with every Serializer class you make.
    """
    for auto_cls in cls.auto_serialized_classes:
        auto_serializers_by_class[auto_cls] = cls

    for auto_json_cls in cls.auto_json_deserialized_classes:
        auto_json_deserializers_by_class[auto_json_cls] = cls

    serializers_by_typecode_byte[cls.typecode_byte] = cls
    serializers_by_type_name[cls.type_name] = cls

    return cls

class Serializer(object):
    """Serialize/deserialize methods for a class

    Generally you won't use these classes directly to actually serialize and
    deserialize objects. Rather you create subclasses of these classes to
    implement your own serialization scheme.
    """

    type_name = 'invalid'
    typecode_byte = b''

    # The list of classes that are automatically serialized using this
    # serialization class. That is, (json|binary)_serialize() will check that
    # obj.__class__ is auto_class, and if so, use this serialization method.
    auto_serialized_classes = ()

    # The list of JSON classes that are automatically deserialized using this
    # serialization class. That is, json_deserialize() will check that
    # json_obj.__class__ is cls, and if so, use this deserialization method.
    auto_json_deserialized_classes = ()

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
            our_fd = cStringIO.StringIO()

        # Write the typecode byte.
        our_fd.write(cls.typecode_byte)

        cls._binary_serialize(obj,our_fd)

        if fd is None:
            our_fd.seek(0)
            return our_fd.read()

    @classmethod
    def _binary_deserialize(cls,obj,fd):
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
            fd = cStringIO.StringIO(fd)

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
        assert False

    return cls.json_deserialize(json_obj)


def binary_serialize(obj,fd=None):
    """Serialize obj to the binary format

    The serialized bytes are written using fd.write(); generally fd will be
    a file descriptor. There is no return value.

    As a convenience for debugging and similar activities, if fd is not set
    this function returns bytes instead.
    """
    our_fd = fd
    if our_fd is None:
        our_fd = cStringIO.StringIO()

    (cls,obj) = get_serializer_for_obj(obj)
    cls.binary_serialize(obj,our_fd)

    if fd is None:
        our_fd.seek(0)
        return our_fd.read()


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
        fd = cStringIO.StringIO(fd)

    typecode_byte = fd.read(1)

    cls = serializers_by_typecode_byte[typecode_byte]

    return cls.binary_deserialize(fd)

@register_serializer
class NullSerializer(Serializer):
    type_name = 'null'
    typecode_byte = typecodes_by_name[type_name]
    auto_serialized_classes = (types.NoneType,)
    auto_json_deserialized_classes = (types.NoneType,)

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
    typecode_byte = typecodes_by_name[type_name]
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
    typecode_byte = typecodes_by_name[type_name]

    @classmethod
    def _binary_serialize(cls,obj,fd):
        while obj >= 0b10000000:
            fd.write(chr((obj & 0b01111111) | 0b10000000))
            obj = obj >> 7
        fd.write(chr((obj & 0b01111111) | 0b00000000))

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
    typecode_byte = typecodes_by_name[type_name]
    auto_serialized_classes = (int,long)
    auto_json_deserialized_classes = (int,long)

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
    typecode_byte = typecodes_by_name[type_name]
    auto_serialized_classes = (bytes,str)
    auto_json_deserialized_classes = ()

    @classmethod
    def json_serialize(cls,obj):
        return u'#' + binascii.hexlify(obj)

    @classmethod
    def json_deserialize(cls,json_obj):
        assert json_obj[0] == u'#'
        return binascii.unhexlify(json_obj[1:])

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
    typecode_byte = typecodes_by_name[type_name]
    auto_serialized_classes = (unicode,)
    auto_json_deserialized_classes = (unicode,)

    @classmethod
    def __utf8_normalize(cls,obj):
        # Ban nulls to make life easier for implementers, particularly C/C++
        # versions.
        if u'\u0000' in obj:
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
                obj = u'\\' + obj
            elif obj[0] == '\\':
                obj = u'\\' + obj
        return obj

    @classmethod
    def json_deserialize(cls,json_obj):
        if len(json_obj) > 0 and json_obj[0] == u'#':
            # This is actually bytes, let the bytes serializer handle it.
            return BytesSerializer.json_deserialize(json_obj)
        elif len(json_obj) > 0 and json_obj[0] == u'\\':
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

@register_serializer
class TypedObjectSerializer(Serializer):
    """Typed object representation

    Basically we need a uniform way to add types to JSON. So we overload the
    dict type as follows:

    {"type_name":<JSON serialization>}

    and the dict serialization code recognizes that special form and calls us.
    Not relevant for the binary serialization, as that has types already.
    """
    type_name = 'invalid'
    typecode_byte = b'\xff'
    auto_serialized_classes = ()
    auto_json_deserialized_classes = ()

    @classmethod
    def json_deserialize(cls,json_obj):
        keys = json_obj.keys()
        assert len(keys) == 1
        type_name = keys[0]

        serializer_cls = serializers_by_type_name[type_name]

        if serializer_cls is DictSerializer:
            # Don't apply the hack recursively.
            return serializer_cls.json_deserialize(json_obj[type_name],do_typed_object_hack=False)
        else:
            return serializer_cls.json_deserialize(json_obj[type_name])

    @classmethod
    def json_serialize(cls,obj):
        (serializer_cls,obj) = get_serializer_for_obj(obj)
        return {serializer_cls.type_name:json_serialize(obj)}

    # Makes no sense to use these as TypedObjectSerializer doesn't have a valid
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
    typecode_byte = typecodes_by_name[type_name]
    auto_serialized_classes = (dict,)
    auto_json_deserialized_classes = (dict,)

    @classmethod
    def __check_key(cls,key):
        if not isinstance(key,str) and not isinstance(key,unicode):
            raise SerializationError("Can't serialize dicts with non-string keys; got %r" % key)
        elif len(key) < 1:
            raise SerializationError("Can't serialize dicts with empty keys")

    @classmethod
    def json_serialize(cls,obj):
        json_obj = {}

        for key,value in obj.items():
            cls.__check_key(key)
            json_obj[key] = json_serialize(value)

        if len(json_obj.keys()) == 1:
            # Hack! Serialize with a typed object wrapper, because otherwise
            # we'll trigger the typed object code.
            json_obj = {u'dict':json_obj}
        return json_obj

    @classmethod
    def json_deserialize(cls,json_obj,do_typed_object_hack=True):
        if len(json_obj.keys()) == 1 and do_typed_object_hack:
            # Hack! This looks like a typed object, so send it to the typed
            # object deserializer.
            return TypedObjectSerializer.json_deserialize(json_obj)

        obj = {}

        for key,value in json_obj.items():
            obj[key] = json_deserialize(value)
        return obj

    @classmethod
    def _binary_serialize(cls,obj,fd):
        for key in sorted(obj.keys()):
            value = obj[key]
            cls.__check_key(key)
            key = unicode(key)
            StrSerializer._binary_serialize(key,fd)

            binary_serialize(value,fd)

        # empty key signals the end
        StrSerializer._binary_serialize(u'',fd)

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
    typecode_byte = typecodes_by_name[type_name]
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
    typecode_byte = typecodes_by_name[type_name]
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
