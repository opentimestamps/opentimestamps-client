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

"""Internal use only"""

import binascii
import os
import shutil
import struct
import sys
import tempfile
import uuid

# hexlify and unhexlify with unicode output
def hexlify(b):
    return binascii.hexlify(b).decode('utf8')
def unhexlify(h):
    return binascii.unhexlify(h.encode('utf8'))


class BinaryHeader(object):
    """Mix-in to deal with binary headers"""

    class UnknownFileTypeError(Exception):
        pass

    class VersionError(Exception):
        pass

    # The UUID makes pretty much guarantees the magic database will return the
    # right file type.
    #
    # The text makes it easy for people to look at the file with strings or
    # hexdump and figure out what it is.
    header_magic_uuid = None
    header_magic_text = None

    # Define these to be what your implementation is. For now, if the major
    # version doesn't match on read, throw an error.
    #
    # Minor version info is informational only for now.
    major_version = None
    minor_version = None

    # Fixed length stuff for your header goes here. Not going to implement
    # different struct formats per version until we actually need that.
    header_struct_format = None
    header_field_names = None

    # If set in your class definition, header will be padded to this length. If
    # unset, after you call read_header() your instance will magically aquire a
    # header_length attribute, set appropriately.
    header_length = None


    __struct_format = None

    def __header_read_write_common(self):
        # Bit of a hack to add this stuff to the self instance, but whatever.
        if self.__struct_format is None:
            self.header_magic_bytes = self.header_magic_uuid.bytes + self.header_magic_text

            self.__struct_format = ('>%ds B B' % len(self.header_magic_bytes)) + self.header_struct_format
            self.__field_names = ['header_magic_bytes','major_version','minor_version'] \
                    + list(self.header_field_names)

            actual_header_length = struct.calcsize(self.__struct_format)

            if self.header_length is None:
                # Wasn't set
                self.header_length = actual_header_length
            elif self.header_length >= actual_header_length:
                # User wants it to be extended as required
                hdr_len_diff = (self.header_length - actual_header_length)
                self.__struct_format += 'x' * hdr_len_diff
            else:
                raise AssertionError(
                    "header_length is too small for %s; needs to be at least %d; you gave %d" %
                        (self.__class__.__name__,actual_header_length,self.header_length))



    def _read_header(self,fd):
        """Read the header from fd

        fd must be at the beginning of the file already.

        If the magic and major version match up, self.__dict__ will be
        populated with the header fields. (including minor_version)
        """
        self.__header_read_write_common()

        hdr_bytes = fd.read(self.header_length)
        hdr_fields = struct.unpack(self.__struct_format,hdr_bytes)
        hdr = dict(list(zip(self.__field_names,hdr_fields)))

        # test magic and version
        if hdr['header_magic_bytes'] != self.header_magic_bytes:
            raise self.UnknownFileTypeError('Unknown file type')
        if hdr['major_version'] != self.major_version:
            raise self.VersionError('Version %d.%d is not supported' % (hdr['major_version'],hdr['minor_version']))

        self.__dict__.update(hdr)


    def _write_header(self,fd):
        """Write the header to fd

        fd must be at the beginning of the file already.
        """
        self.__header_read_write_common()

        hdr_fields = []
        h = self.__field_names
        for f in self.__field_names:
            hdr_fields.append(getattr(self,f))

        fd.write(struct.pack(self.__struct_format,*hdr_fields))


class FileManager(object):
    """Work with filenames from the command line safely

    Handles '-' referring to stdin/stdout and safely re-writes files in-place
    if required. Files will not be left half finished.

    Tip: If you don't actually need an input (or even output) just set the
         appropriate name to '-' and don't use the associated file descriptor.

    Usage:

    with FileManager('foo') as foo_file:
        contents = read(foo_file.in_fd)
        write(foo_file.out_fd,contents)

        foo_file.commit()
    """

    # The following probably has problems on windows. It probably also still
    # contains race conditions, especially if you do weird stuff with moving
    # symbolic links around.
    #
    # Also, since we turn given filenames into real filenames, dereferencing
    # symbolic links, error messages might be confusing to the user...

    def __init__(self,
                 existing_filename,new_filename=None,
                 dash_for_stdinout=True,
                 in_mode='rb',
                 out_mode='wb+',
                 stdin=None,
                 stdout=None):

        self.in_mode = in_mode
        self.out_mode = out_mode

        if not stdin:
            if 'b' in in_mode:
                stdin = sys.stdin.buffer
            else:
                stdin = sys.stdin
        self.stdin = stdin
        if not stdout:
            if 'b' in out_mode:
                stdout = sys.stdout.buffer
            else:
                stdout = sys.stdout
        self.stdout = stdout

        self.dash_for_stdinout = dash_for_stdinout

        self.existing_filename = existing_filename
        self.in_place = False
        if new_filename is None:
            new_filename = existing_filename
            self.in_place = True
        self.new_filename = new_filename


    def __enter__(self):
        """Enter context

        A temporary file will be created for new_fd; new_filename is not
        touched.
        """
        # Open files, if required, and create a temp file for the output, again
        # if required.

        if self.dash_for_stdinout and self.existing_filename == '-':
            self.in_is_a_file = False
            self.in_fd = self.stdin
        else:
            self.in_is_a_file = True
            self.real_existing_filename = os.path.realpath(self.existing_filename)
            self.in_fd = open(self.real_existing_filename,self.in_mode)

            # This is set if we later move the existing file out of the way
            # after commit()
            self.moved_existing_filename = None

        if self.dash_for_stdinout and self.new_filename == '-':
            self.out_is_a_file = False
            self.out_fd = self.stdout
        else:
            self.out_is_a_file = True
            self.real_new_filename = os.path.realpath(self.new_filename)
            self.out_fd = tempfile.NamedTemporaryFile(
                                     mode = self.out_mode,
                                     prefix = os.path.basename(self.real_new_filename),
                                     dir = os.path.dirname(self.real_new_filename),
                                     delete=False)
            self.new_temp_filename = self.out_fd.name

        return self

    def __exit__(self,exc_type,exc_value,exc_tb):
        """Close context

        Temporary files are removed and in_fd and out_fd are closed if they
        were files.
        """
        if self.in_is_a_file and self.moved_existing_filename is not None:
            self.in_fd.close()
            try:
                os.remove(self.moved_existing_filename)
            except OSError:
                pass

        if self.out_is_a_file and self.new_temp_filename is not None:
            self.out_fd.close()
            try:
                os.remove(self.new_temp_filename)
            except OSError:
                pass

        if self.in_is_a_file:
            self.in_fd.close()
        if self.out_is_a_file:
            self.out_fd.close()


    def commit(self):
        """Commit changes to disk

        out_fd is flushed and fsynced if it is a file.

        If applicable until this point both the new and old files have not been
        changed irrevocably; out_fd is a temporary file and out_filename has
        not been touched.

        After calling commit() both in_fd and out_fd are still valid, but the
        files referred to by new_filename and and old_filename (if overwritten
        in-place) will have changed.
        """

        if not self.out_is_a_file:
            return

        self.out_fd.flush()
        os.fsync(self.out_fd.fileno())

        if self.in_is_a_file and self.out_is_a_file \
            and (os.path.realpath(self.existing_filename)
                     == os.path.realpath(self.new_filename)):

            # New will overwrite existing, so move existing out of the way
            self.moved_existing_filename = tempfile.mktemp(
                    prefix=os.path.basename(self.real_existing_filename),
                    dir=os.path.dirname(self.real_existing_filename))

            # Note the race condition...
            os.rename(self.real_existing_filename,self.moved_existing_filename)


        # Note that we could have also just deleted existing, but windows can't
        # rename atomically, and it's nicer to keep it around until the very
        # last minute.
        os.rename(self.new_temp_filename,self.real_new_filename)

        # Set permissions correctly for our new file.
        if self.in_place:
            # Copy permissions over, so that from the user's point of view it
            # looks like the file was just edited.
            shutil.copymode(self.moved_existing_filename,self.real_new_filename)

        else:
            # Not in-place, although quite possibly the existing and new
            # filenames were the same.
            #
            # NamedTemporaryFile creates files with a hard-coded 0600 as the mode,
            # so if we didn't overwrite-in-place, set mode based on umask.
            our_umask = os.umask(0)
            os.umask(our_umask) # gah, wish there was a get_umask...
            os.chmod(self.real_new_filename,~our_umask & 0o666)

        # FIXME: windows support
