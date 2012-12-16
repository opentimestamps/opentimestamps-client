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
import io
import json

from ..dag import *

def make_op_round_trip_tester(self):
    def r(value,expected_representation=None,new_value=None):
        # serialize to primitives
        actual_representation = value.to_primitives()
        if expected_representation is not None:
            self.assertEqual(actual_representation,expected_representation)

        # take that representation and send it through a json parser
        post_json_representation = json.loads(json.dumps(actual_representation))

        # deserialize that and check if it's what we expect
        value2 = Op.from_primitives(post_json_representation)
        if new_value is not None:
            value = new_value
        self.assertEqual(value,value2)
    return r

class TestOp(unittest.TestCase):
    def test_equality(self):
        a1 = Digest(b'a')
        a2 = Digest(b'a')
        b = Digest(b'b')

        self.assertNotEqual(a1,object())

        self.assertEqual(a1,a2)
        self.assertEqual(a1,b'a')
        self.assertEqual(b,b'b')
        self.assertNotEqual(a1,b)
        self.assertNotEqual(a2,b)

    def test___hash__(self):
        a1 = Digest(b'a')
        a2 = Digest(b'a')
        b = Digest(b'b')

        s = set((a1,b))

        self.assertIn(b,s)
        self.assertIn(a1,s)
        self.assertIn(a2,s)

        a2.foo = 'bar'
        self.assertIn(a2,s)

class TestDigestOp(unittest.TestCase):
    def test_json_serialization(self):
        r = make_op_round_trip_tester(self)

        d = Digest(b'\xff\x00')
        r(d,{'Digest': {'input': 'ff00', 'digest': 'ff00', 'parents': []}})


class TestXOROp(unittest.TestCase):
    def test(self):
        # XOR requires at least one parent to be specified, so make our own
        # function to deal with that.
        def xor(input,*args,**kwargs):
            return XOR(input,*args,parents=((input,)))

        with self.assertRaises(ValueError):
            xor(b'')
        with self.assertRaises(ValueError):
            xor(b'1')
        with self.assertRaises(ValueError):
            xor(b'123')

        self.assertEqual(xor(b'\x00\x00'),b'\x00')
        self.assertEqual(xor(b'\x00\xff'),b'\xff')
        self.assertEqual(xor(b'\xff\xff'),b'\x00')
        self.assertEqual(xor(b'abcdefgh'),b'\x04\x04\x04\x0c')

    def test_json_serialization(self):
        r = make_op_round_trip_tester(self)

        d = XOR(b'\xff',b'\x00',parents=((b'\xff',)))
        r(d,{'XOR': {'input': 'ff00', 'digest': 'ff', 'parents': [(0,1)]}})


class TestHashOp(unittest.TestCase):
    def test_hash_algorithm_support(self):
        def t(algo,expected,d=(b'',)):
            h = Hash(*d,algorithm=algo)
            self.assertEqual(h,expected)

        t('sha256d',b']\xf6\xe0\xe2v\x13Y\xd3\n\x82u\x05\x8e)\x9f\xcc\x03\x81SEE\xf5\\\xf4>A\x98?]L\x94V')
        t('sha512d',b'\x82m\xf0hE}\xf5\xdd\x19[Cz\xb7\xe7s\x9f\xf7]&r\x18?\x02\xbb\x8e\x10\x89\xfa\xbc\xf9{\xd9\xdc\x80\x11\x0c\xf4-\xbc|\xffA\xc7\x8e\xcbh\xd8\xbax\xab\xe6\xb5\x17\x8d\xea9\x84\xdf\x8cUT\x1b\xf9I')

        t('crc32',b'\x00\x00\x00\x00')
        t('crc32',b':,\xcd\x8d',d=(b"Testing an awful hash algorithm.",))

    def test_json_serialization(self):
        r = make_op_round_trip_tester(self)

        h1 = Hash(b'a',b'b')
        r(h1,{'Hash':
                {'input':'6162',
                 'parents': [(0,1), (1,1)],
                 'algorithm':'sha256d',
                 'digest':'a1ff8f1856b5e24e32e3882edd4a021f48f28a8b21854b77fdef25a97601aace'}})


class TestDag(unittest.TestCase):
    # TODO: we need a Dag conformance test basically, one that all Dag
    # implementations must pass.
    #
    # Actually, the same applies for Digest, Hash and Verify
    #
    # TODO: also, add test to ensure _swap_input_obj swaps all inputs, even if
    # the same object is presence multiple times.
    def test_in_operator(self):
        dag = Dag()

        self.assertFalse(b'' in dag)
        self.assertFalse(b'd' in dag)
        self.assertFalse(Digest(b'd') in dag)

        d = dag.add(Digest(b'd'))

        self.assertTrue(b'd' in dag)
        self.assertTrue(d in dag)

        d2 = Digest(b'd')
        self.assertTrue(d2 in dag)

        self.assertFalse(b'' in dag)


    def test_getitem_operator(self):
        dag = Dag()

        with self.assertRaises(KeyError):
            dag[1]
        with self.assertRaises(KeyError):
            dag[b'']
        with self.assertRaises(KeyError):
            dag[Digest(b'd')]

        d = dag.add(Digest(b'd'))

        self.assertIs(dag[d],d)

        d2 = Digest(b'd')
        self.assertIs(dag[d2],d)


    def test_dependencies(self):
        dag = Dag()

        self.assertTrue(len(tuple(dag)) == 0)

        # Basic insertion
        d1a = Digest(b'd1')
        d1 = dag.add(d1a)
        self.assertEqual(dag[d1a],d1)

        h_not_in_dag = Hash(d1)
        self.assertEqual(dag[d1a],d1)

        # does not change d1 dependencies
        self.assertEqual(len(dag.dependents[d1]),0)

        # inserted a digest identical to h1
        d2 = dag.add(Digest(h_not_in_dag))
        self.assertEqual(dag[d2],d2)

        # recreate as a more interesting object
        h_in_dag = dag.add(Hash(d1))
        self.assertEqual(h_in_dag,d2)
        self.assertEqual(dag[d2],h_in_dag)

        # d1 now marks h_in_dag as a dependency
        self.assertIn(h_in_dag,dag.dependents[d1])

        h2 = dag.add(Hash(h_in_dag,d1))
        self.assertIn(h2,dag.dependents[d1])
        self.assertIn(h2,dag.dependents[h_in_dag])

    def test_op_removal(self):
        # FIXME
        pass


    def test_path(self):
        n = 100
        dag = Dag()
        def r(start,dest,expected_path):
            def tuple_or_none(v):
                if v is None:
                    return v
                else:
                    return tuple(v)
            self.assertEqual(
                    tuple_or_none(dag.path(start,dest)),
                    tuple_or_none(expected_path))

        # Create a linked chain of digests
        chain = [Hash(b'')]
        for i in range(1,n):
            chain.append(Hash(chain[i - 1]))

        r(chain[0],chain[0],[chain[0]])
        r(chain[0],chain[1],None)


        # Add some of the chain back in.
        dag.add(chain[0])
        r(chain[0],chain[1],None)
        dag.add(chain[1])
        r(chain[0],chain[1],(chain[1],))
        r(chain[0],chain[2],None)

        # Add the rest
        for i in range(2,n):
            dag.add(chain[i])

        r(chain[0],chain[n-1],chain[1:])
        r(chain[n-1],chain[0],None)


class Test_build_merkle_tree(unittest.TestCase):
    def test(self):
        def t(n,algorithm=None):
            dag = Dag()
            parents = [Digest(bytes(str(i),'utf8')) for i in range(0,n)]

            tree = build_merkle_tree(parents,algorithm=algorithm)

            dag.update(parents)
            dag.update(tree)

            # The whole tree has a path to the tree child.
            max_path = 0
            for d in tree:
                path = tuple(dag.path(d,tree[-1]))
                self.assertFalse(path is None)
                self.assertTrue(len(path) > 0)
                max_path = max(max_path,len(path))

            # Parents have paths to the tree child
            min_path = 2**32
            avg_path = 0
            for d in parents:
                path = tuple(dag.path(d,tree[-1]))
                self.assertFalse(path is None)
                self.assertTrue(len(path) > 0)
                avg_path += len(path)
                min_path = min(len(path),min_path)
                max_path = max(max_path,len(path))

            # Check path lengths are all reasonable
            from math import log
            avg_path /= float(len(parents))
            expected_path = log(n,2)
            self.assertLess(max_path,expected_path+1)
            self.assertGreater(min_path,expected_path/2)
            self.assertTrue(expected_path - 1 < avg_path < expected_path + 1)

        with self.assertRaises(ValueError):
            build_merkle_tree(())

        d = Digest(b'd')
        self.assertSequenceEqual(build_merkle_tree((d,)),(d,))

        for i in (3,4,5,10,21,64,513):
            t(i)
