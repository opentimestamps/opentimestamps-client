# Copyright (C) 2016 The OpenTimestamps developers
#
# This file is part of python-opentimestamps.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-opentimestamps including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import binascii

from bitcoin.core import CTransaction, SerializationError, b2lx, b2x

from opentimestamps.core.op import Op, CryptOp, OpSHA256, OpAppend, OpPrepend, MsgValueError
from opentimestamps.core.notary import TimeAttestation, BitcoinBlockHeaderAttestation

import opentimestamps.core.serialize

class OpSet(dict):
    """Set of operations"""
    __slots__ = ['__make_timestamp']
    def __init__(self, make_timestamp_func):
        self.__make_timestamp = make_timestamp_func

    def add(self, key):
        """Add key

        Returns the value associated with that key
        """
        try:
            return self[key]
        except KeyError:
            value = self.__make_timestamp(key)
            self[key] = value
            return value

    def __setitem__(self, op, new_timestamp):
        try:
            existing_timestamp = self[op]
        except KeyError:
            dict.__setitem__(self, op, new_timestamp)
            return

        if existing_timestamp.msg != new_timestamp.msg:
            raise ValueError("Can't change existing result timestamp: timestamps are for different messages")

        dict.__setitem__(self, op, new_timestamp)

class Timestamp:
    """Proof that one or more attestations commit to a message

    The proof is in the form of a tree, with each node being a message, and the
    edges being operations acting on those messages. The leafs of the tree are
    attestations that attest to the time that messages in the tree existed prior.
    """
    __slots__ = ['__msg', 'attestations', 'ops']

    @property
    def msg(self):
        return self.__msg

    def __init__(self, msg):
        if not isinstance(msg, bytes):
            raise TypeError("Expected msg to be bytes; got %r" % msg.__class__)

        elif len(msg) > Op.MAX_MSG_LENGTH:
            raise ValueError("Message exceeds Op length limit; %d > %d" % (len(msg), Op.MAX_MSG_LENGTH))

        self.__msg = bytes(msg)
        self.attestations = set()
        self.ops = OpSet(lambda op: Timestamp(op(msg)))

    def __eq__(self, other):
        if isinstance(other, Timestamp):
            return self.__msg == other.__msg and self.ops == other.ops
        else:
            return False

    def __repr__(self):
        return 'Timestamp(<%s>)' % binascii.hexlify(self.__msg).decode('utf8')

    def merge(self, other):
        """Add all operations and attestations from another timestamp to this one

        Raises ValueError if the other timestamp isn't for the same message
        """
        if not isinstance(other, Timestamp):
            raise TypeError("Can only merge Timestamps together")

        if self.__msg != other.__msg:
            raise ValueError("Can't merge timestamps for different messages together")

        self.attestations.update(other.attestations)

        for other_op, other_op_stamp in other.ops.items():
            our_op_stamp = self.ops.add(other_op)
            our_op_stamp.merge(other_op_stamp)

    def serialize(self, ctx):
        if not len(self.attestations) and not len(self.ops):
            raise ValueError("An empty timestamp can't be serialized")

        sorted_attestations = sorted(self.attestations)
        if len(sorted_attestations) > 1:
            for attestation in sorted_attestations[0:-1]:
                ctx.write_bytes(b'\xff\x00')
                attestation.serialize(ctx)

        if len(self.ops) == 0:
            ctx.write_bytes(b'\x00')
            sorted_attestations[-1].serialize(ctx)

        elif len(self.ops) > 0:
            if len(sorted_attestations) > 0:
                ctx.write_bytes(b'\xff\x00')
                sorted_attestations[-1].serialize(ctx)

            sorted_ops = sorted(self.ops.items(), key=lambda item: item[0])
            for op, stamp in sorted_ops[0:-1]:
                ctx.write_bytes(b'\xff')
                op.serialize(ctx)
                stamp.serialize(ctx)

            last_op, last_stamp = sorted_ops[-1]
            last_op.serialize(ctx)
            last_stamp.serialize(ctx)

    @classmethod
    def deserialize(cls, ctx, initial_msg, _recursion_limit=256):
        """Deserialize

        Because the serialization format doesn't include the message that the
        timestamp operates on, you have to provide it so that the correct
        operation results can be calculated.

        The message you provide is assumed to be correct; if it causes a op to
        raise MsgValueError when the results are being calculated (done
        immediately, not lazily) DeserializationError is raised instead.
        """

        # FIXME: The recursion limit is arguably a bit of a hack given that
        # it's relatively easily avoided with a different implementation. On
        # the other hand, it has the advantage of being a very simple
        # solution to the problem, and the limit isn't likely to be reached by
        # nearly all timestamps anyway.
        #
        # FIXME: Corresponding code to detect this condition is missing from
        # the serialization/__init__() code.
        if not _recursion_limit:
            raise opentimestamps.core.serialize.RecursionLimitError("Reached timestamp recursion depth limit while deserializing")

        # FIXME: note how a lazy implementation would have different behavior
        # with respect to deserialization errors; is this a good design?

        self = cls(initial_msg)

        def do_tag_or_attestation(tag):
            if tag == b'\x00':
                attestation = TimeAttestation.deserialize(ctx)
                self.attestations.add(attestation)

            else:
                op = Op.deserialize_from_tag(ctx, tag)

                try:
                    result = op(initial_msg)
                except MsgValueError as exp:
                    raise opentimestamps.core.serialize.DeserializationError("Invalid timestamp; message invalid for op %r: %r" % (op, exp))

                stamp = Timestamp.deserialize(ctx, result, _recursion_limit=_recursion_limit-1)
                self.ops[op] = stamp

        tag = ctx.read_bytes(1)
        while tag == b'\xff':
            do_tag_or_attestation(ctx.read_bytes(1))

            tag = ctx.read_bytes(1)

        do_tag_or_attestation(tag)

        return self

    def all_attestations(self):
        """Iterate over all attestations recursively

        Returns iterable of (msg, attestation)
        """
        for attestation in self.attestations:
            yield (self.msg, attestation)

        for op_stamp in self.ops.values():
            yield from op_stamp.all_attestations()

    def str_tree(self, indent=0, verbosity=0):
        """Convert to tree (for debugging)"""

        class bcolors:
            HEADER = '\033[95m'
            OKBLUE = '\033[94m'
            OKGREEN = '\033[92m'
            WARNING = '\033[93m'
            FAIL = '\033[91m'
            ENDC = '\033[0m'
            BOLD = '\033[1m'
            UNDERLINE = '\033[4m'

        def str_result(verb, parameter, result):
            rr = ""
            if verb > 0 and result is not None:
                rr += " == "
                result_hex = b2x(result)
                if parameter is not None:
                    parameter_hex = b2x(parameter)
                    try:
                        index = result_hex.index(parameter_hex)
                        parameter_hex_highlight = bcolors.BOLD + parameter_hex + bcolors.ENDC
                        if index == 0:
                            rr += parameter_hex_highlight + result_hex[index+len(parameter_hex):]
                        else:
                            rr += result_hex[0:index] + parameter_hex_highlight
                    except ValueError:
                        rr += result_hex
                else:
                    rr += result_hex

            return rr

        r = ""
        if len(self.attestations) > 0:
            for attestation in sorted(self.attestations):
                r += " "*indent + "verify %s" % str(attestation) + str_result(verbosity, self.msg, None) + "\n"
                if attestation.__class__ == BitcoinBlockHeaderAttestation:
                    r += " "*indent + "# Bitcoin block merkle root " + b2lx(self.msg) + "\n"

        if len(self.ops) > 1:
            for op, timestamp in sorted(self.ops.items()):
                try:
                    CTransaction.deserialize(self.msg)
                    r += " " * indent + "* Bitcoin transaction id " + b2lx(
                        OpSHA256()(OpSHA256()(self.msg))) + "\n"
                except SerializationError:
                    pass
                cur_res = op(self.msg)
                cur_par = op[0]
                r += " " * indent + " -> " + "%s" % str(op) + str_result(verbosity, cur_par, cur_res) + "\n"
                r += timestamp.str_tree(indent+4, verbosity=verbosity)
        elif len(self.ops) > 0:
            try:
                CTransaction.deserialize(self.msg)
                r += " " * indent + "# Bitcoin transaction id " + \
                     b2lx(OpSHA256()(OpSHA256()(self.msg))) + "\n"
            except SerializationError:
                pass
            op = tuple(self.ops.keys())[0]
            cur_res = op(self.msg)
            cur_par = op[0] if len(op) > 0 else None
            r += " " * indent + "%s" % str(op) + str_result(verbosity, cur_par, cur_res) + "\n"
            r += tuple(self.ops.values())[0].str_tree(indent, verbosity=verbosity)

        return r


class DetachedTimestampFile:
    """A file containing a timestamp for another file

    Contains a timestamp, along with a header and the digest of the file.
    """

    HEADER_MAGIC = b'\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94'
    """Header magic bytes

    Designed to be give the user some information in a hexdump, while being
    identified as 'data' by the file utility.
    """

    MIN_FILE_DIGEST_LENGTH = 20 # 160-bit hash
    MAX_FILE_DIGEST_LENGTH = 32 # 256-bit hash

    MAJOR_VERSION = 1

    # While the git commit timestamps have a minor version, probably better to
    # leave it out here: unlike Git commits round-tripping is an issue when
    # timestamps are upgraded, and we could end up with bugs related to not
    # saving/updating minor version numbers correctly.

    @property
    def file_digest(self):
        """The digest of the file that was timestamped"""
        return self.timestamp.msg

    def __init__(self, file_hash_op, timestamp):
        self.file_hash_op = file_hash_op

        if len(timestamp.msg) != file_hash_op.DIGEST_LENGTH:
            raise ValueError("Timestamp message length and file_hash_op digest length differ")

        self.timestamp = timestamp

    def __repr__(self):
        return 'DetachedTimestampFile(<%s:%s>)' % (str(self.file_hash_op), binascii.hexlify(self.file_digest).decode('utf8'))

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.file_hash_op == other.file_hash_op and
                self.timestamp == other.timestamp)

    @classmethod
    def from_fd(cls, file_hash_op, fd):
        fd_hash = file_hash_op.hash_fd(fd)
        return cls(file_hash_op, Timestamp(fd_hash))

    def serialize(self, ctx):
        ctx.write_bytes(self.HEADER_MAGIC)

        ctx.write_varuint(self.MAJOR_VERSION)

        self.file_hash_op.serialize(ctx)
        assert self.file_hash_op.DIGEST_LENGTH == len(self.timestamp.msg)
        ctx.write_bytes(self.timestamp.msg)

        self.timestamp.serialize(ctx)

    @classmethod
    def deserialize(cls, ctx):
        ctx.assert_magic(cls.HEADER_MAGIC)

        major = ctx.read_varuint() # FIXME: max-int limit
        if major != cls.MAJOR_VERSION:
            raise opentimestamps.core.serialize.UnsupportedMajorVersion("Version %d detached timestamp files are not supported" % major)

        file_hash_op = CryptOp.deserialize(ctx)
        file_hash = ctx.read_bytes(file_hash_op.DIGEST_LENGTH)
        timestamp = Timestamp.deserialize(ctx, file_hash)

        ctx.assert_eof()

        return DetachedTimestampFile(file_hash_op, timestamp)


def cat_then_unary_op(unary_op_cls, left, right):
    """Concatenate left and right, then perform a unary operation on them

    left and right can be either timestamps or bytes.

    Appropriate intermediary append/prepend operations will be created as
    needed for left and right.
    """
    if not isinstance(left, Timestamp):
        left = Timestamp(left)

    if not isinstance(right, Timestamp):
        right = Timestamp(right)

    left_append_stamp = left.ops.add(OpAppend(right.msg))
    right_prepend_stamp = right.ops.add(OpPrepend(left.msg))

    # Left and right should produce the same thing, so we can set the timestamp
    # of the left to the right.
    left.ops[OpAppend(right.msg)] = right_prepend_stamp

    return right_prepend_stamp.ops.add(unary_op_cls())


def cat_sha256(left, right):
    return cat_then_unary_op(OpSHA256, left, right)


def cat_sha256d(left, right):
    sha256_timestamp = cat_sha256(left, right)
    return sha256_timestamp.ops.add(OpSHA256())


def make_merkle_tree(timestamps, binop=cat_sha256):
    """Merkelize a set of timestamps

    A merkle tree of all the timestamps is built in-place using binop() to
    timestamp each pair of timestamps. The exact algorithm used is structurally
    identical to a merkle-mountain-range, although leaf sums aren't committed.
    As this function is under the consensus-critical core, it's guaranteed that
    the algorithm will not be changed in the future.

    Returns the timestamp for the tip of the tree.
    """

    stamps = timestamps
    while True:
        stamps = iter(stamps)

        try:
            prev_stamp = next(stamps)
        except StopIteration:
            raise ValueError("Need at least one timestamp")

        next_stamps = []
        for stamp in stamps:
            if prev_stamp is not None:
                next_stamps.append(binop(prev_stamp, stamp))
                prev_stamp = None
            else:
                prev_stamp = stamp

        if not next_stamps:
            return prev_stamp

        if prev_stamp is not None:
            next_stamps.append(prev_stamp)

        stamps = next_stamps
