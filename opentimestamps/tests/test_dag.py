# Copyright (C) 2012-2013 Peter Todd <pete@petertodd.org>
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

    def test_parents_can_be_empty(self):
        Digest(b'foo', parents=())
        Digest(b'foo', parents=[])

    def test_parents_must_be_valid(self):
        with self.assertRaises(ValueError):
            Digest(b'foo', parents=((-1,1),))
        with self.assertRaises(ValueError):
            Digest(b'foo', parents=((0,0),))
        Digest(b'foo', parents=((0,3),))
        Digest(b'foo', parents=((2,1),))
        with self.assertRaises(ValueError):
            Digest(b'foo', parents=((0,4),))
        with self.assertRaises(ValueError):
            Digest(b'foo', parents=((0,5),))
        with self.assertRaises(ValueError):
            Digest(b'foo', parents=((3,1),))
        with self.assertRaises(ValueError):
            Digest(b'foo', parents=((4,1),))
        with self.assertRaises(ValueError):
            Digest(b'foo', parents=(b'bar',))
        with self.assertRaises(ValueError):
            Digest(b'foo', parents=(b'',))

    def test_compression(self):
        def t(stack, op, expected_prims):
            from_stack = [digest for digest, idx in sorted(stack.items(), key=lambda p: p[1])]

            actual_prims = op.to_primitives(digest_stack=stack, include_digest=False)
            round_trip_op = Op.from_primitives(actual_prims, digest_stack=from_stack)

            op_type = list(actual_prims.keys())[0]
            actual_prims[op_type].pop('metadata')  # not important
            actual_prims[op_type].pop('algorithm', False) # ditto
            self.assertEqual(expected_prims, actual_prims)

            self.assertEqual(op, round_trip_op)
            self.assertEqual(op.parents, round_trip_op.parents)


        t({}, Hash(b'a', parents=()), {'Hash':{'input': ['61'], 'parents': []}})

        t({b'a':0}, Hash(b'a', parents=(b'a',)), {'Hash':{'input': [1], 'parents': [(0, 1)]}})
        t({b'a':0}, Hash(b'a', b'a', parents=(b'a',)), {'Hash':{'input': [1, 1], 'parents': [(0, 1)]}})
        t({b'a':0}, Hash(b'a', b'foo', b'a', parents=(b'a',)),
                {'Hash':{'input': [1, '666f6f', 1], 'parents': [(0, 1)]}})

        t({b'a':0}, Hash(b'a', b'foo', b'a', parents=(b'a', b'fooa')),
                {'Hash':{'input': [1, '666f6f', 1], 'parents': [(0, 1), (1, 4)]}})
        t({b'a':0, b'fooa':1}, Hash(b'a', b'foo', b'a', parents=(b'a', b'fooa')),
                {'Hash':{'input': [2, 1], 'parents': [(0, 1), (1, 4)]}})

        # Check that if the input itself is in the stack, it's compressed even
        # if it's not in the "parents" list.
        t({b'a':0}, Digest(b'a'), {'Digest':{'input': [1], 'parents': []}})
        t({b'a':0}, Hash(b'a', parents=()), {'Hash':{'input': [1], 'parents': []}})


class TestDigestOp(unittest.TestCase):
    def test_json_serialization(self):
        r = make_op_round_trip_tester(self)

        d = Digest(b'\xff\x00')
        r(d,{'Digest': {'input': ['ff00'], 'digest': 'ff00', 'parents': [], 'metadata': {}}})



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
                {'input':['6162'],
                 'parents': [(0,1), (1,1)],
                 'algorithm':'sha256d',
                 'metadata': {},
                 'digest':'a1ff8f1856b5e24e32e3882edd4a021f48f28a8b21854b77fdef25a97601aace'}})


class Test_valid_path(unittest.TestCase):
    def test(self):
        start = b'o\xe2\x8c\n\xb6\xf1\xb3r\xc1\xa6\xa2F\xaec\xf7O\x93\x1e\x83e\xe1Z\x08\x9ch\xd6\x19\x00\x00\x00\x00\x00'

        path = [Hash(b'\x01\x00\x00\x00',b'o\xe2\x8c\n\xb6\xf1\xb3r\xc1\xa6\xa2F\xaec\xf7O\x93\x1e\x83e\xe1Z\x08\x9ch\xd6\x19\x00\x00\x00\x00\x00',b'\x98 Q\xfd\x1eK\xa7D\xbb\xbeh\x0e\x1f\xee\x14g{\xa1\xa3\xc3T\x0b\xf7\xb1\xcd\xb6\x06\xe8W#>\x0e',b'a\xbcfI\xff\xff\x00\x1d\x01\xe3b\x99', algorithm='sha256d'),
                Hash(b'\x01\x00\x00\x00',b'H`\xeb\x18\xbf\x1b\x16 \xe3~\x94\x90\xfc\x8aBu\x14Ao\xd7QY\xab\x86h\x8e\x9a\x83\x00\x00\x00\x00',b'\xd5\xfd\xccT\x1e%\xde\x1czZ\xdd\xed\xf2HX\xb8\xbbf\\\x9f6\xeftN\xe4,1`"\xc9\x0f\x9b',b'\xb0\xbcfI\xff\xff\x00\x1d\x08\xd2\xbda',algorithm='sha256d'),
                Hash(b'\x01\x00\x00\x00',b'\xbd\xdd\x99\xcc\xfd\xa3\x9d\xa1\xb1\x08\xce\x1a]p\x03\x8d\n\x96{\xac\xb6\x8bkc\x06_bj\x00\x00\x00\x00',b'D\xf6r"`\x90\xd8]\xb9\xa9\xf2\xfb\xfe_\x0f\x96\t\xb3\x87\xaf{\xe5\xb7\xfb\xb7\xa1v|\x83\x1c\x9e\x99',b']\xbefI\xff\xff\x00\x1d\x05\xe0\xedm',algorithm='sha256d'),
                Hash(b'\x01\x00\x00\x00',b'IDF\x95b\xae\x1c,t\xd9\xa55\xe0\x0bo>@\xff\xba\xd4\xf2\xfd\xa3\x89U\x01\xb5\x82\x00\x00\x00\x00',b'z\x06\xea\x98\xcd@\xba.2\x88&+(c\x8c\xecS7\xc1Ej\xaf^\xed\xc8\xe9\xe5\xa2\x0f\x06+\xdf',b'\x8c\xc1fI\xff\xff\x00\x1d+\xfe\xe0\xa9',algorithm='sha256d'),
                Hash(b'\x01\x00\x00\x00',b'\x85\x14J\x84H\x8e\xa8\x8d"\x1c\x8b\xd6\xc0Y\xda\t\x0e\x88\xf8\xa2\xc9\x96\x90\xeeU\xdb\xbaN\x00\x00\x00\x00',b'\xe1\x1cH\xfe\xcd\xd9\xe7%\x10\xca\x84\xf0#7\x0c\x9a8\xbf\x91\xac\\\xae\x88\x01\x9b\xee\x94\xd2E(Rc',b'D\xc3fI\xff\xff\x00\x1d\x1d\x03\xe4w',algorithm='sha256d')]

        self.assertTrue(valid_path(start, []))
        self.assertTrue(valid_path(start, path))
        self.assertTrue(valid_path(start, path[:-1]))
        self.assertTrue(valid_path(start, path[:-2]))
        self.assertTrue(valid_path(start, path[:-3]))
        self.assertFalse(valid_path(b'foo', path))
        self.assertFalse(valid_path(start, path[1:]))
        self.assertFalse(valid_path(start, path[2:]))

        # only parents is checked, not the input itself
        path[0] = Hash(path[0].input, parents=())
        self.assertFalse(valid_path(start, path))


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


    def test_roots(self):
        dag = Dag()
        self.assertEqual(dag.roots(), set())

        d1 = Digest(b'd1')
        dag.add(d1)
        self.assertEqual(dag.roots(), set((d1,)))

        d2 = Digest(b'd2')
        dag.add(d2)
        self.assertEqual(dag.roots(), set((d1,d2)))

        # not a root
        h12 = Hash(d1, d2)
        dag.add(h12)
        self.assertEqual(dag.roots(), set((d1,d2)))

        # h3 is root as it depends on a digest outside of the dag
        d3 = Digest(b'd3')
        h3 = Hash(d3)
        dag.add(h3)
        self.assertEqual(dag.roots(), set((d1,d2,h3)))

        # no longer a root
        dag.add(d3)
        self.assertEqual(dag.roots(), set((d1,d2,d3)))

    def test_tsort(self):
        import random
        def create_random_dag(num_roots, num_deps, max_parents):
            dag = Dag()

            dag.update([Digest(bytes(str(i), 'utf8')) for i in range(num_roots)])

            for i in range(num_deps):
                deps = []
                for j in range(random.randint(1, max(max_parents, len(dag)))):
                    deps.append(random.choice(list(dag)))
                dag.add(Hash(*deps))

            return dag


        def check_topo_sort(l):
            seen = set()
            for n in l:
                if n.parents.difference(seen):
                    return False
                seen.add(n)
            return True

        # check that our check function actually works
        l = []
        l.append(Digest(b'eggs'))
        l.append(Digest(b'ham'))
        l.append(Hash(l[0]))
        l.append(Hash(l[0], l[1]))

        self.assertTrue(check_topo_sort(l))
        self.assertFalse(check_topo_sort(reversed(l)))

        dag = create_random_dag(100, 100, 100)
        sort = dag.tsort()

        self.assertTrue(dag == set(sort))

        self.assertTrue(check_topo_sort(sort))
        self.assertFalse(check_topo_sort(reversed(sort)))

        # test that tsort is deterministic
        sort2 = Dag(dag).tsort()
        self.assertTrue(sort == sort2)


    def test_children(self):
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

        r(chain[0],chain[0],[])
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
