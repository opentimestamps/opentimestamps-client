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

from opentimestamps.serialization import *

from copy import copy
import io
import json
import unittest

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
            binary_deserialize(b'\xff')



class TestUIntSerialization(unittest.TestCase):
    def test_varint_serialization(self):
        def r(value,expected_representation):
            fd = io.BytesIO()
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
            fd = io.BytesIO()
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
        r(int( 0),b'\x02\x00')
        r(int(-1),b'\x02\x01')
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

        r(b'','#')
        r(b'\xff','#ff')
        r(b'\x00','#00')
        r(b'\x00\x11\x22','#001122')

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

        r('','')
        r('foo','foo')

        # Escape #'s at the start of a string.
        r('#','\\#')
        r('###','\\###')
        r('# 2324','\\# 2324')

        # Also, \'s at the start of a string need to be escaped as well.
        r('\\','\\\\')
        r('\\# 2324','\\\\# 2324')

        # NFC normalization example: <A + grave> is transformed into À
        r('\u0041\u0300','\u00c0','\u00c0')

    def test_binary_serialization(self):
        r = make_binary_round_trip_tester(self)

        r('',b'\x04\x00')
        r('foo',b'\x04\x03foo')

        # NFC normalization example: <A + grave> is transformed into À
        r('\u0041\u0300',b'\x04\x02\xc3\x80','\u00c0')

        with self.assertRaises(ValueError):
            StrSerializer.binary_serialize('foo \u0000')
        with self.assertRaises(ValueError):
            StrSerializer.json_serialize('foo \u0000')
        with self.assertRaises(ValueError):
            json_serialize('foo \u0000')
        with self.assertRaises(ValueError):
            binary_serialize('foo \u0000')


class TestJsonTypedObjectSerializer(unittest.TestCase):
    def test_typed_json_syntax_for_basic_types(self):
        def r(obj_in,expected_json,expected_out):
            actual_json = JsonTypedObjectSerializer.json_serialize(obj_in)
            self.assertEqual(expected_json,actual_json)

            actual_out = json_deserialize(actual_json)
            self.assertEqual(expected_out,actual_out)

        r({},{'dict':{}},{})
        r(1,{'int':1},1)
        r('foo',{'str':'foo'},'foo')
        r([1,2,b'\xff'],{'list':[1,2,'#ff']},[1,2,b'\xff'])



class TestDictSerialization(unittest.TestCase):
    def test_json_serialization(self):
        r = make_json_round_trip_tester(self)

        r({},{})

        # Note the str and unicode key's
        r({'a':'b','c':1},{'a':'b','c':1})
        r({'a':'b','c':{}},{'a':'b','c':{}})
        r({'a':'b','c':{'a':5,'b':b'\xff'}},{'a':'b','c':{'a':5,'b':'#ff'}})

        # non-str keys should fail
        with self.assertRaises(SerializationError):
            json_serialize({1:2,3:4})

        # empty keys should fail
        with self.assertRaises(SerializationError):
            json_serialize({'':2,'foo':4})

        # Trigger the typed object hack.
        r({'a':None},{'dict':{'a':None}})

    def test_binary_serialization(self):
        r = make_binary_round_trip_tester(self)

        r({},b'\x06\x00')

        # Note the str and unicode key's
        r({'a':'b','c':{}},b'\x06\x01a\x04\x01b\x01c\x06\x00\x00')

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
        r([b'\xff'],['#ff'])
        r([b'\xff',[[[False,'hi there']]]],['#ff',[[[False,'hi there']]]])

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


@serialized_object_subclass('TestSerializedObject')
class SerializedClass(SerializedObject):
    serialized_attributes = ('class1',)

    def __init__(self,*args,**kwargs):
        self.args = copy(args)
        self.kwargs = copy(kwargs)
        super().__init__(**kwargs)

@serialized_object_subclass('TestSerializedObject')
class SerializedSubClass1(SerializedClass):
    serialized_attributes = ('subclass1',)

@serialized_object_subclass('TestSerializedObject')
class SerializedSubClass2(SerializedClass):
    serialized_attributes = ('subclass2',)

@serialized_object_subclass('TestSerializedObject')
class SerializedMultiple(SerializedSubClass1,SerializedSubClass2):
    serialized_attributes = ('multiple',)

class TestSerializedObject(unittest.TestCase):
    def test_single_class(self):
        self.assertSetEqual(SerializedClass.all_serialized_attributes,set(('class1',)))

    def test_subclasses(self):
        self.assertSetEqual(SerializedSubClass1.all_serialized_attributes,set(('class1','subclass1')))
        self.assertSetEqual(SerializedSubClass2.all_serialized_attributes,set(('class1','subclass2')))

    def test_diamond_inheritence(self):
        self.assertSetEqual(\
            SerializedMultiple.all_serialized_attributes,
            set(('class1','subclass1','subclass2','multiple')))

    def test_setting_conflicting_serialized_attributes_fails(self):
        with self.assertRaises(AttributeError):
            class Conflicts1(SerializedClass):
                serialized_attributes = ('class1',)
            serialized_object_subclass('TestSerializedObject')(Conflicts1)

        with self.assertRaises(AttributeError):
            class Conflicts2(SerializedSubClass1):
                serialized_attributes = ('class1',)
            serialized_object_subclass('TestSerializedObject')(Conflicts2)

    def test_serialization_deserialization(self):
        m = SerializedMultiple()

        self.assertEqual(
                json_serialize(m),
                {'TestSerializedObject.SerializedMultiple': {}})

        m.multiple = 'multi'
        self.assertEqual(
                json_serialize(m),
                {'TestSerializedObject.SerializedMultiple': {'multiple':'multi'}})

        m.class1 = 'class1'
        self.assertEqual(
                json_serialize(m),
                {'TestSerializedObject.SerializedMultiple':
                    {'class1':'class1',
                     'multiple':'multi'}})

        m.subclass1 = 1
        self.assertEqual(
                json_serialize(m),
                {'TestSerializedObject.SerializedMultiple':
                    {'class1':'class1',
                     'multiple':'multi',
                     'subclass1':1}})

        m.subclass2 = 2
        self.assertEqual(
                json_serialize(m),
                {'TestSerializedObject.SerializedMultiple':
                    {'class1':'class1',
                     'multiple':'multi',
                     'subclass1':1,
                     'subclass2':2}})

        m.not_serialized = 'foo'
        self.assertEqual(
                json_serialize(m),
                {'TestSerializedObject.SerializedMultiple': 
                    {'class1':'class1',
                     'multiple':'multi',
                     'subclass1':1,
                     'subclass2':2}})

        m2 = json_deserialize(json_serialize(m))
        self.assertEqual(
                json_serialize(m),
                {'TestSerializedObject.SerializedMultiple':
                    {'class1':'class1',
                     'multiple':'multi',
                     'subclass1':1,
                     'subclass2':2}})

    def test_unknown_attributes_are_kept_out_of_kwargs(self):
        obj = json_deserialize({'TestSerializedObject.SerializedClass': {'unknown':None}})

        self.assertEqual(
                obj.kwargs,
                {'_SerializedObject_unknown_attributes': {'unknown': None},
                 '_SerializedObjectSerializer_type_name': 'TestSerializedObject.SerializedClass'})

    def test_invalid_type_names(self):
        with self.assertRaises(SerializationTypeNameInvalidError):
            json_deserialize({'*':{}})

        with self.assertRaises(SerializationTypeNameInvalidError):
            json_deserialize({None:{}})

        with self.assertRaises(SerializationTypeNameInvalidError):
            # Empty type name
            binary_deserialize(b'\t\x00\x00')

        with self.assertRaises(SerializationTypeNameInvalidError):
            # Invalid character in type name
            binary_deserialize(b'\t\x01*\x00')


    def test_deserializing_unknown_object_types(self):
        def rj(json_obj):
            actual_obj = json_deserialize(json_obj)
            json_obj2 = json_serialize(actual_obj)
            self.assertEqual(json_obj,json_obj2)

        def rb(binary_obj):
            actual_obj = binary_deserialize(binary_obj)
            binary_obj2 = binary_serialize(actual_obj)
            self.assertEqual(binary_obj,binary_obj2)

        rj({'unknown.foo':{}})

        rj({'unknown.foo':{'foo':10,'bar':None}})

        rb(b'\t\x0bunknown.foo\x00')



@digestible_serialized_object_subclass('TestDigestible')
class DigestibleFoo(DigestibleSerializedObject):
    digested_attributes = ('digested',)

# Two different digestible classes, but they always produce the same digest!
@digestible_serialized_object_subclass('TestDigestible')
class DigestibleSameDigest1(DigestibleSerializedObject):
    digested_attributes = ('digested',)
    def calculate_digest(self):
        return b'groundhog day'

@digestible_serialized_object_subclass('TestDigestible')
class DigestibleSameDigest2(DigestibleSerializedObject):
    digested_attributes = ('digested',)
    def calculate_digest(self):
        return b'groundhog day'

@digestible_serialized_object_subclass('TestDigestible')
class DigestibleMutatableDigest(DigestibleSerializedObject):
    digested_attributes = ('digested',)
    def calculate_digest(self):
        return self.mutatable_digest


class TestDigestible(unittest.TestCase):
    def digestsEqual(self,a,b):
        self.assertEqual(a,b)
        self.assertEqual(hash(a),hash(b))
    def digestsNotEqual(self,a,b):
        self.assertNotEqual(a,b)
        self.assertNotEqual(hash(a),hash(b))

    def test_digests_are_tested_solely_by_digest(self):
        a = DigestibleSameDigest1()
        b = DigestibleSameDigest2()
        a.lock()
        b.lock()
        self.digestsEqual(a,b)

    def test_digests_are_calculated_once(self):
        a = DigestibleMutatableDigest()
        a.mutatable_digest = b'a'
        a.lock()

        a2 = DigestibleMutatableDigest()
        a2.mutatable_digest = b'a'
        a2.lock()

        b = DigestibleMutatableDigest()
        b.mutatable_digest = b'b'
        b.lock()

        self.digestsEqual(a,a)
        self.digestsEqual(a,a2)
        self.digestsNotEqual(a,b)

        a2.mutatable_digest = b'b'
        b.mutatable_digest = b'a'
        self.digestsEqual(a,a2)
        self.digestsNotEqual(a,b)


    def test_digest_must_be_bytes(self):
        a = DigestibleMutatableDigest()
        a.mutatable_digest = None

        with self.assertRaises(TypeError):
            a.lock()

        a.mutatable_digest = bytearray(b'foo')
        with self.assertRaises(TypeError):
            a.lock()

        class bytes_subclass(bytes):
            pass

        a.mutable_digest = bytes_subclass(b'foo')
        with self.assertRaises(TypeError):
            a.lock()

    def test_digest_attribute_is_immutable(self):
        a = DigestibleFoo()

        with self.assertRaises(AttributeError):
            a.digest = None
        with self.assertRaises(AttributeError):
            del a.digest

        a.lock()
        with self.assertRaises(AttributeError):
            a.digest = None
        with self.assertRaises(AttributeError):
            del a.digest

    def test_attribute_locking(self):
        a = DigestibleFoo()
        a.lock()
        with self.assertRaises(AttributeError):
            a.digested = None
        self.assertFalse(hasattr(a,'digested'))

        a = DigestibleFoo()
        a.digested = 'deleted'
        del a.digested
        a.digested = 'not deleted'
        a.lock()
        with self.assertRaises(AttributeError):
            a.digested = None
        with self.assertRaises(AttributeError):
            del a.digested
        self.assertEqual(a.digested,'not deleted')

    def test_equality(self):
        a = DigestibleFoo()
        b = DigestibleFoo()
        b.undigested = 'asdf'

        # Can test for equality with an unrelated object before locking.
        self.assertFalse(a == None)
        self.assertFalse(None == a)
        self.assertFalse(a.__eq__(None))

        # Can not test for equality with other Digestibles if either is
        # unlocked.
        with self.assertRaises(ValueError):
            self.assertEqual(a,b)
        a.lock()
        with self.assertRaises(ValueError):
            self.assertEqual(a,b)
        b.lock()

        self.assertEqual(a,b)
        b.undigested = 'qwer'
        self.assertEqual(a,b)

        b2 = DigestibleFoo()
        b2.digested = None
        b2.lock()
        self.assertNotEqual(a,b2)

        b3 = DigestibleFoo()
        b3.digested = b2
        b3.lock()
        self.assertNotEqual(a,b3)

    def test_order_comparison(self):
        a = DigestibleMutatableDigest()
        a.mutatable_digest = b'a'
        a.lock()

        b = DigestibleMutatableDigest()
        b.mutatable_digest = b'b'
        b.lock()

        self.assertTrue(a <= a)
        self.assertTrue(a <= b)
        self.assertTrue(a < b)
        self.assertTrue(b > a)
        self.assertTrue(b >= a)
        self.assertTrue(b >= b)

        a = DigestibleMutatableDigest()
        a.mutatable_digest = b'aa'
        a.lock()

        b = DigestibleMutatableDigest()
        b.mutatable_digest = b'bb'
        b.lock()

        self.assertTrue(a <= a)
        self.assertTrue(a <= b)
        self.assertTrue(a < b)
        self.assertTrue(b > a)
        self.assertTrue(b >= a)
        self.assertTrue(b >= b)


    def test_hashing(self):
        a = DigestibleFoo()
        b = DigestibleFoo()

        with self.assertRaises(ValueError):
            hash(a)
        a.lock()
        b.lock()

        self.assertEqual(hash(a),hash(b))

        b2 = DigestibleFoo()
        b2.undigested = 'asdf'
        b2.lock()
        self.assertEqual(hash(a),hash(b2))

        b3 = DigestibleFoo()
        b3.digested = a
        b3.lock()
        self.assertNotEqual(hash(a),hash(b3))

    def test_locking(self):
        f = DigestibleFoo()
        with self.assertRaises(AttributeError):
            f.locked = True

        # Won't lock if there are unlocked Digestible attribute values.
        f.digested = DigestibleFoo()
        with self.assertRaises(ValueError):
            f.lock()
        self.assertFalse(f.locked)

        f.digested.lock()
        f.lock()

        self.assertEqual(f.digest,
b'\x06\x1cTestDigestible.DigestibleFoo\x06\x08digested\x05!\x06\x1cTestDigestible.DigestibleFoo\x06\x00\x00\x00\x00')
