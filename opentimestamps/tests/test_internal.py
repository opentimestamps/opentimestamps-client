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

import os
import shutil
import stat
import sys
import tempfile
import unittest

from .._internal import FileManager

class TestFileManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix='tmpFileManager')

        # Need to leave at least group write/exec to be able to check that
        # permissions get moved over appropriately.
        self.old_umask = os.umask(0o002)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        os.umask(self.old_umask)

    def mktemp(self):
        return tempfile.mktemp(dir=self.temp_dir)

    def NamedTemporaryFile(self,**kwargs):
        return tempfile.NamedTemporaryFile(dir=self.temp_dir,**kwargs)

    def set_file_contents(self,magic):
        """Create a temporary file and put something in it

        Returns the new file name.
        """
        new_fd = self.NamedTemporaryFile(delete=False)
        new_fd.write(magic)
        new_name = new_fd.name
        new_fd.close()
        return new_name

    def check_file_contents(self,name,magic):
        """Fail if a file doesn't have some magic bytes in it"""
        fd = open(name,'rb')
        self.assertEqual(fd.read(),magic)
        fd.close()

    def check_file_mode(self,name,expected_mode=0o664):
        """Fail if file doesn't have expected mode"""
        st = os.stat(name)
        self.assertEqual(oct(stat.S_IMODE(st.st_mode)),oct(expected_mode))


    def test_stdin_stdout(self):
        fake_stdin = tempfile.TemporaryFile()
        fake_stdout = tempfile.TemporaryFile()

        fake_stdin.write(b'in magic')
        fake_stdin.seek(0,0)

        with FileManager('-','-',stdin=fake_stdin,stdout=fake_stdout) as f:
            self.assertEqual(f.in_fd.read(),b'in magic')
            f.out_fd.write(b'out magic')

        fake_stdout.seek(0,0)
        self.assertEqual(fake_stdout.read(),b'out magic')


    def test_stdin_file(self):
        fake_stdin = tempfile.TemporaryFile()
        new_name = self.mktemp()

        fake_stdin.write(b'stdin_file_in_magic')
        fake_stdin.seek(0,0)

        saved_out_fd = None
        with FileManager('-',new_name,stdin=fake_stdin) as f:
            saved_out_fd = f.out_fd

            self.assertFalse(os.path.exists(new_name))
            f.out_fd.write(b'stdin_file_out_magic1')

            f.commit()

            self.assertEqual(f.in_fd.read(),b'stdin_file_in_magic')

            self.assertTrue(os.path.exists(new_name))
            f.out_fd.write(b'magic2')

            self.check_file_mode(new_name)

        self.assertTrue(saved_out_fd.closed)
        self.check_file_contents(new_name,b'stdin_file_out_magic1magic2')

        # errors keep old contents
        with self.assertRaises(Exception):
            with FileManager('-',new_name,stdin=fake_stdin) as f:
                saved_out_fd = f.out_fd
                f.out_fd.write(b'these changes are thrown away')
                raise Exception()

        self.assertTrue(saved_out_fd.closed)
        self.check_file_contents(new_name,b'stdin_file_out_magic1magic2')


    def test_file_file_different(self):
        old_name = self.set_file_contents(b'file_file_different_in')
        new_name = self.mktemp()

        saved_in_fd = None
        saved_out_fd = None
        with FileManager(old_name,new_name) as f:
            saved_in_fd = f.in_fd
            saved_out_fd = f.out_fd

            self.assertFalse(os.path.exists(new_name))
            f.out_fd.write(b'file_file_different_out_magic1')

            f.commit()

            f.out_fd.write(b'magic2')

            self.assertTrue(os.path.exists(new_name))
            self.check_file_mode(new_name)

        # Make sure in_fd and out_fd have been closed.
        self.assertTrue(saved_in_fd.closed)
        self.assertTrue(saved_out_fd.closed)

        self.check_file_contents(new_name,b'file_file_different_out_magic1magic2')


        # errors keep old contents
        with self.assertRaises(Exception):
            with FileManager('-',new_name,stdin=fake_stdin) as f:
                saved_out_fd = f.out_fd
                f.out_fd.write(b'these changes are thrown away')
                raise Exception()

        self.assertTrue(saved_out_fd.closed)
        self.check_file_contents(new_name,b'file_file_different_out_magic1magic2')

    def test_file_file_inplace(self):
        # File changed in-place
        old_name = self.set_file_contents(b'file_file_inplace_in')
        new_name = old_name

        # Give it some odd permissions
        os.chmod(old_name,0o610)

        saved_in_fd = None
        saved_out_fd = None
        with FileManager(old_name) as f:
            saved_in_fd = f.in_fd
            saved_out_fd = f.out_fd

            self.assertTrue(os.path.exists(new_name))
            f.out_fd.write(b'file_file_inplace_out_magic1')

            self.check_file_contents(old_name,b'file_file_inplace_in')
            f.commit()
            self.assertTrue(os.path.exists(new_name))

            # New file does gets weird permissions
            self.check_file_mode(new_name,0o610)

            f.out_fd.write(b'magic2')

        # Make sure in_fd and out_fd have been closed.
        self.assertTrue(saved_in_fd.closed)
        self.assertTrue(saved_out_fd.closed)

        self.check_file_contents(new_name,b'file_file_inplace_out_magic1magic2')


        # errors keep old contents
        with self.assertRaises(Exception):
            with FileManager('-',new_name,stdin=fake_stdin) as f:
                saved_out_fd = f.out_fd
                f.out_fd.write(b'these changes are thrown away')
                raise Exception()

        self.assertTrue(saved_out_fd.closed)
        self.check_file_contents(new_name,b'file_file_inplace_out_magic1magic2')


    def test_file_file_same(self):
        # Both names refer to the same file. We'll be tricky though, and use
        # symlinks to make it look like they aren't the same file.
        #
        # Of course, if this is handled correctly, relative paths-vs-absolute
        # and similar must work too.
        os.mkdir(self.temp_dir + '/real_dir')
        old_name = self.temp_dir + '/real_dir/foo'

        os.symlink(self.temp_dir + '/real_dir',self.temp_dir + '/fake_dir')
        new_name = self.temp_dir + '/fake_dir/foo'

        # Create existing, but give it some odd permissions.
        with open(old_name,'wb') as fd:
            fd.write(b'magic')
        os.chmod(old_name,0o610)

        saved_in_fd = None
        saved_out_fd = None
        with FileManager(old_name,new_name) as f:
            saved_in_fd = f.in_fd
            saved_out_fd = f.out_fd

            self.assertTrue(os.path.exists(new_name))
            f.out_fd.write(b'out magic1')

            f.commit()
            self.assertTrue(os.path.exists(new_name))

            # New file does *not* get weird permissions, not an in-place change
            self.check_file_mode(new_name)

            f.out_fd.write(b'magic2')

        # Make sure in_fd and out_fd have been closed.
        self.assertTrue(saved_in_fd.closed)
        self.assertTrue(saved_out_fd.closed)

        self.check_file_contents(new_name,b'out magic1magic2')


        # errors keep old contents
        with self.assertRaises(Exception):
            with FileManager('-',new_name,stdin=fake_stdin) as f:
                saved_out_fd = f.out_fd
                f.out_fd.write(b'these changes are thrown away')
                raise Exception()

        self.assertTrue(saved_out_fd.closed)
        self.check_file_contents(new_name,b'out magic1magic2')
