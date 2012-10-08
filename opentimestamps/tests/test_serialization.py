# vim: set fileencoding=utf8
#
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

import unittest
import StringIO
import json

from ..serialization import *
def make_json_round_trip_tester(self):
    def r(value,expected_representation,new_value=None):
        # serialize to json-compat representation
        actual_representation = json_serialize(value)
        self.assertEqual(actual_representation,expected_representation)

        # take that representation and send it through a json parser
        post_json_representation = json.loads(json.dumps(actual_representation))

        # deserialize that and check if it's what we expect
        value2 = json_deserialize(post_json_representation)
        if new_value is not None:
            value = new_value
        self.assertEqual(value,value2)
    return r

def make_binary_round_trip_tester(self):
    def r(value,expected_representation,new_value=None):
        # serialize to binary representation
        actual_representation = binary_serialize(value)
        self.assertEqual(actual_representation,expected_representation)

        # deserialize that and check if it's what we expect
        value2 = binary_deserialize(actual_representation)
        if new_value is not None:
            value = new_value
        self.assertEqual(value,value2)
    return r

class TestNoneSerialization(unittest.TestCase):
    def test_json_serialization(self):
        r = make_json_round_trip_tester(self)
        r(None,None)

    def test_binary_serialization(self):
        r = make_binary_round_trip_tester(self)
        r(None,b'\x00')

class TestBoolSerialization(unittest.TestCase):
    def test_json_serialization(self):
        r = make_json_round_trip_tester(self)
        r(True,True)
        r(False,False)

    def test_binary_serialization(self):
        r = make_binary_round_trip_tester(self)
        r(True,b'\x01\xff')
        r(False,b'\x01\x00')

        with self.assertRaises(SerializationError):
            BoolSerializer.binary_deserialize(b'\x42')


class Test(unittest.TestCase):
    def test_unknown_types_raise_errors_binary(self):
        with self.assertRaises(SerializationUnknownTypeError):
            json_deserialize({'invalid':None})
        with self.assertRaises(SerializationUnknownTypeError):
            json_deserialize({'invalid':{}})

    def test_unknown_types_raise_errors_binary(self):
        with self.assertRaises(SerializationUnknownTypeCodeError):
            binary_deserialize('\xff')



class TestUIntSerialization(unittest.TestCase):
    def test_varint_serialization(self):
        def r(value,expected_representation):
            fd = StringIO.StringIO()
            UIntSerializer._binary_serialize(value,fd)

            fd.seek(0)
            actual_representation = fd.read()

            self.assertEqual(expected_representation,actual_representation)

            fd.seek(0)
            value2 = UIntSerializer._binary_deserialize(fd)

            self.assertEqual(value,value2)

        r(0,b'\x00')
        r(1,b'\x01')
        r(126,b'\x7e')
        r(127,b'\x7f')
        r(128,b'\x80\x01')
        r(255,b'\xff\x01')
        r(256,b'\x80\x02')
        r(16383,b'\xff\x7f')
        r(16384,b'\x80\x80\x01')
        r(16385,b'\x81\x80\x01')
        r(2097151,b'\xff\xff\x7f')
        r(2097152,b'\x80\x80\x80\x01')
        r(2097153,b'\x81\x80\x80\x01')

        # 128**5, over 2**32
        r(34359738367,b'\xff\xff\xff\xff\x7f')
        r(34359738368,b'\x80\x80\x80\x80\x80\x01')
        r(34359738369,b'\x81\x80\x80\x80\x80\x01')

        # 128**10, over 2**64
        r(1180591620717411303423,b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f')
        r(1180591620717411303424,b'\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01')
        r(1180591620717411303425,b'\x81\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01')


class TestIntSerialization(unittest.TestCase):
    def test_zigzag_serialization(self):
        # round trip
        def r(value,expected_representation):
            fd = StringIO.StringIO()
            IntSerializer._binary_serialize(value,fd)

            fd.seek(0)
            actual_representation = fd.read()

            if expected_representation is not None:
                self.assertEqual(expected_representation,actual_representation)

            fd.seek(0)
            value2 = IntSerializer._binary_deserialize(fd)

            self.assertEqual(value,value2)

        r(0,b'\x00')

        r(-1,b'\x01')
        r( 1,b'\x02')

        r(-5,b'\x09')
        r( 5,b'\x0a')

        r(-64,b'\x7f')
        r(-65,b'\x81\x01')
        r(-66,b'\x83\x01')
        r( 63,b'\x7e')
        r( 64,b'\x80\x01')
        r( 65,b'\x82\x01')

        r(-128,b'\xff\x01')
        r(-129,b'\x81\x02')
        r(-130,b'\x83\x02')
        r( 126,b'\xfc\x01')
        r( 127,b'\xfe\x01')
        r( 128,b'\x80\x02')

        r(-8192,b'\xff\x7f')
        r(-8193,b'\x81\x80\x01')
        r(-8194,b'\x83\x80\x01')
        r( 8191,b'\xfe\x7f')
        r( 8192,b'\x80\x80\x01')
        r( 8193,b'\x82\x80\x01')

    def test_auto_binary_serialization(self):
        def r(value,expected_representation):
            actual_representation = binary_serialize(value)
            self.assertEqual(actual_representation,expected_representation)

            value2 = binary_deserialize(actual_representation)
            self.assertEqual(value,value2)

        r( 0,b'\x02\x00')
        r(-1,b'\x02\x01')

        # long ints
        r(long( 0),b'\x02\x00')
        r(long(-1),b'\x02\x01')
        r(2**31,b'\x02\x80\x80\x80\x80\x10')
        r(-2**31,b'\x02\xff\xff\xff\xff\x0f')
        r(2**65,b'\x02\x80\x80\x80\x80\x80\x80\x80\x80\x80\x08')
        r(-2**65,b'\x02\xff\xff\xff\xff\xff\xff\xff\xff\xff\x07')

    def test_auto_json_serialization(self):
        def r(value,expected_representation):
            actual_representation = json_serialize(value)
            self.assertEqual(actual_representation,expected_representation)

            value2 = json_deserialize(actual_representation)
            self.assertEqual(value,value2)

        r(0,0)
        r(2**32,2**32)

class TestBytesSerialization(unittest.TestCase):
    def test_json_serialization(self):
        r = make_json_round_trip_tester(self)

        r(b'',u'#')
        r(b'\xff',u'#ff')
        r(b'\x00',u'#00')
        r(b'\x00\x11\x22',u'#001122')

    def test_binary_serialization(self):
        r = make_binary_round_trip_tester(self)

        r(b'',b'\x05\x00')
        r(b'foo',b'\x05\x03foo')

        r(b'\x00foo',b'\x05\x04\x00foo')

        # Long strings
        def rl(c,l,l_encoded):
            r(b'.'*l,b'\x05' + l_encoded + b'.'*l)
        rl(b'.',1,b'\x01')
        rl(b'.',2,b'\x02')
        rl(b'.',127,b'\x7f')
        rl(b'.',16383,b'\xff\x7f')
        rl(b'.',16384,b'\x80\x80\x01')

class TestStrSerialization(unittest.TestCase):
    def test_json_serialization(self):
        r = make_json_round_trip_tester(self)

        r(u'',u'')
        r(u'foo',u'foo')

        # Escape #'s at the start of a string.
        r(u'#',u'\\#')
        r(u'###',u'\\###')
        r(u'# 2324',u'\\# 2324')

        # Also, \'s at the start of a string need to be escaped as well.
        r(u'\\',u'\\\\')
        r(u'\\# 2324',u'\\\\# 2324')

        # NFC normalization example: <A + grave> is transformed into À
        r(u'\u0041\u0300',u'\u00c0',u'\u00c0')

    def test_binary_serialization(self):
        r = make_binary_round_trip_tester(self)

        r(u'',b'\x04\x00')
        r(u'foo',b'\x04\x03foo')

        # NFC normalization example: <A + grave> is transformed into À
        r(u'\u0041\u0300',b'\x04\x02\xc3\x80',u'\u00c0')

        with self.assertRaises(ValueError):
            StrSerializer.binary_serialize(u'foo \u0000')
        with self.assertRaises(ValueError):
            StrSerializer.json_serialize(u'foo \u0000')
        with self.assertRaises(ValueError):
            json_serialize(u'foo \u0000')
        with self.assertRaises(ValueError):
            binary_serialize(u'foo \u0000')


class TestObjectSerializer(unittest.TestCase):
    def test_custom_object_serializer(self):
        rj = make_json_round_trip_tester(self)
        rb = make_binary_round_trip_tester(self)

        class Foo(object):
            def __init__(iself,*args,**kwargs):
                self.assertTrue(len(args) == 0)
                iself.__dict__.update(kwargs)

            def __eq__(self,other):
                return self.__dict__ == other.__dict__ and self.__class__ is other.__class__

        @register_serializer
        class FooSerializer(ObjectSerializer):
            instantiator = Foo
            auto_serialized_classes = (Foo,)
            type_name = 'test.Foo'


        f = Foo()
        rj(f,{u'test.Foo':{}},f)

        f.bar = 1
        rj(f,{u'test.Foo':{'bar':1}},f)

        f2 = Foo()
        f.f2 = f2
        rj(f,{u'test.Foo':{'bar':1,'f2':{u'test.Foo':{}}}},f)

        rb(f,b'\t\x08test.Foo\x03bar\x02\x02\x02f2\t\x08test.Foo\x00\x00',f)


    def test_invalid_type_names(self):
        with self.assertRaises(SerializationTypeNameInvalidError):
            json_deserialize({u'*':{}})

        with self.assertRaises(SerializationTypeNameInvalidError):
            json_deserialize({None:{}})

        with self.assertRaises(SerializationTypeNameInvalidError):
            # Empty type name
            binary_deserialize(b'\t\x00\x00')

        with self.assertRaises(SerializationTypeNameInvalidError):
            # Invalid character in type name
            binary_deserialize(b'\t\x01*\x00')


    def test_deserializing_unknown_object_types(self):
        def rj(json_obj,expected_obj):
            actual_obj = json_deserialize(json_obj)
            self.assertEquals(actual_obj,expected_obj)

        def rb(serialized_representation,expected_obj):
            actual_obj = binary_deserialize(serialized_representation)
            self.assertEquals(actual_obj,expected_obj)

        rj({u'unknown.foo':{}},UnknownTypeOfSerializedObject(_ots_unknown_obj_type_name=u'unknown.foo'))
        rj({u'unknown.foo':{u'foo':10,u'bar':None}},
                UnknownTypeOfSerializedObject(_ots_unknown_obj_type_name=u'unknown.foo',bar=None,foo=10))

        rb(b'\t\x0bunknown.foo\x00',
            UnknownTypeOfSerializedObject(_ots_unknown_obj_type_name=u'unknown.foo'))


    def test_unknown_object_sane_repr(self):
        """Make sure UnknownTypeOfSerializedObjectect has a sane repr()"""
        o = json_deserialize({u'unknown.foo':{}})
        self.assertEquals(repr(o),"UnknownTypeOfSerializedObject(_ots_unknown_obj_type_name=u'unknown.foo')")
        o.foo = 10
        o.bar = None
        self.assertEquals(repr(o),
                "UnknownTypeOfSerializedObject(_ots_unknown_obj_type_name=u'unknown.foo',bar=None,foo=10)")


class TestJsonTypedObjectSerializer(unittest.TestCase):
    def test_typed_json_syntax_for_basic_types(self):
        def r(obj_in,expected_json,expected_out):
            actual_json = JsonTypedObjectSerializer.json_serialize(obj_in)
            self.assertEqual(expected_json,actual_json)

            actual_out = json_deserialize(actual_json)
            self.assertEqual(expected_out,actual_out)

        r({},{u'dict':{}},{})
        r(1,{u'int':1},1)
        r(u'foo',{u'str':u'foo'},u'foo')
        r([1,2,b'\xff'],{u'list':[1,2,'#ff']},[1,2,b'\xff'])



class TestDictSerialization(unittest.TestCase):
    def test_json_serialization(self):
        r = make_json_round_trip_tester(self)

        r({},{})

        # Note the str and unicode key's
        r({'a':u'b',u'c':1},{u'a':u'b',u'c':1})
        r({'a':u'b',u'c':{}},{u'a':u'b',u'c':{}})
        r({'a':u'b',u'c':{'a':5,'b':b'\xff'}},{u'a':u'b',u'c':{u'a':5,u'b':u'#ff'}})

        # non-str keys should fail
        with self.assertRaises(SerializationError):
            json_serialize({1:2,3:4})

        # empty keys should fail
        with self.assertRaises(SerializationError):
            json_serialize({'':2,'foo':4})

        # Trigger the typed object hack.
        r({'a':None},{u'dict':{u'a':None}})

    def test_binary_serialization(self):
        r = make_binary_round_trip_tester(self)

        r({},b'\x06\x00')

        # Note the str and unicode key's
        r({'a':u'b',u'c':{}},b'\x06\x01a\x04\x01b\x01c\x06\x00\x00')

        # non-str keys should fail
        with self.assertRaises(SerializationError):
            binary_serialize({1:2,3:4})

        # empty keys should fail
        with self.assertRaises(SerializationError):
            binary_serialize({'':2,'foo':4})

        # Typed object hack does not apply for the binary serialization method.
        r({'a':None},b'\x06\x01a\x00\x00')

class TestListSerialization(unittest.TestCase):
    def test_json_serialization(self):
        r = make_json_round_trip_tester(self)

        r([],[])
        r((),[],[])

        r([None,False,True,1,2,3],[None,False,True,1,2,3])
        r([b'\xff'],[u'#ff'])
        r([b'\xff',[[[False,u'hi there']]]],[u'#ff',[[[False,u'hi there']]]])

        # Generators should work
        nones_list = [None for i in range(0,128)]
        r((None for i in range(0,128)),nones_list,nones_list)

        # Also iterators should work
        r(iter([None for i in range(0,128)]),nones_list,nones_list)

    def test_binary_serialization(self):
        r = make_binary_round_trip_tester(self)

        r([],b'\x07\x08')
        r((),b'\x07\x08',[])

        r([None],b'\x07\x00\x08')
        r([None,True],b'\x07\x00\x01\xff\x08')

        # Generators should work
        r((None for i in range(0,128)),b'\x07' + b'\x00'*128 + b'\x08',list(None for i in range(0,128)))

        # Also iterators should work
        r(iter([None for i in range(0,128)]),b'\x07' + b'\x00'*128 + b'\x08',list(None for i in range(0,128)))
