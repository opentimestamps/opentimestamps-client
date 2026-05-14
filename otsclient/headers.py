# Copyright (C) 2026 The OpenTimestamps developers
#
# This file is part of the OpenTimestamps Client.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of the OpenTimestamps Client, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

"""Bitcoin block header sources for OpenTimestamps verification.

Provides a small abstraction over "where do we get a block header from" so
that verification can use either a local Bitcoin node (existing behavior),
a local on-disk archive of block headers (this module's main feature), or
any future source via the BlockHeaderSource interface.

The on-disk archive is an append-only file of canonically-serialized
80-byte Bitcoin block headers with a 16-byte file-level header. At 80
bytes per block, the entire Bitcoin chain since 2009 fits in ~70 MB.
This makes archival-quality, fully offline OTS verification practical.
"""

import logging
import os
import struct
import urllib.request

import bitcoin
import bitcoin.core


# On-disk archive format
#
# A header archive starts with a 16-byte file-level header:
#
#   bytes  | field        | description
#   -------+--------------+----------------------------------------------
#   0..3   | magic        | 'OTSH' (4 ASCII bytes)
#   4      | version_major| currently 1
#   5      | version_minor| currently 0
#   6      | network      | 0=mainnet, 1=testnet, 2=regtest
#   7      | reserved     | 0x00
#   8..11  | start_height | uint32 little-endian; height of the first
#                        |   block header stored in this archive
#   12..15 | reserved     | 4 bytes, zero
#
# Followed by N consecutive 80-byte block headers. Block N (for the lowest
# N stored) is at offset 16; block N+1 at offset 16+80; etc.

ARCHIVE_MAGIC = b'OTSH'
ARCHIVE_VERSION_MAJOR = 1
ARCHIVE_VERSION_MINOR = 0
ARCHIVE_FILE_HEADER_SIZE = 16
BLOCK_HEADER_SIZE = 80

NETWORK_ID_MAINNET = 0
NETWORK_ID_TESTNET = 1
NETWORK_ID_REGTEST = 2

NETWORK_NAME_TO_ID = {
    'mainnet': NETWORK_ID_MAINNET,
    'testnet': NETWORK_ID_TESTNET,
    'regtest': NETWORK_ID_REGTEST,
}

NETWORK_ID_TO_NAME = {v: k for k, v in NETWORK_NAME_TO_ID.items()}


class HeaderArchiveError(Exception):
    """Base class for header archive errors."""


class HeaderArchiveFormatError(HeaderArchiveError):
    """Raised when an archive file is malformed or has the wrong magic."""


class HeaderArchiveNetworkMismatch(HeaderArchiveError):
    """Raised when an archive was built for a different network than requested."""


class HeaderArchiveChainError(HeaderArchiveError):
    """Raised when an archive fails prev-hash continuity or PoW validation."""


class HeaderArchive:
    """Read-write append-only archive of Bitcoin block headers.

    Headers are stored sequentially starting at `start_height`. The archive
    file may be opened in read mode (default) or read-write mode for
    appending new headers.
    """

    def __init__(self, path):
        self.path = path

    def exists(self):
        return os.path.isfile(self.path)

    def create(self, network, start_height):
        """Create a new empty archive for the given network and start height.

        Writes the 16-byte file header and nothing else.
        Raises HeaderArchiveError if the file already exists.
        """
        if os.path.exists(self.path):
            raise HeaderArchiveError("Archive file already exists: %s" % self.path)

        if network not in NETWORK_NAME_TO_ID:
            raise HeaderArchiveError("Unknown network: %s" % network)

        os.makedirs(os.path.dirname(self.path) or '.', exist_ok=True)
        with open(self.path, 'wb') as fd:
            fd.write(self._pack_file_header(network, start_height))

    def _pack_file_header(self, network, start_height):
        return struct.pack(
            '<4sBBBBI4s',
            ARCHIVE_MAGIC,
            ARCHIVE_VERSION_MAJOR,
            ARCHIVE_VERSION_MINOR,
            NETWORK_NAME_TO_ID[network],
            0,  # reserved byte
            start_height,
            b'\x00\x00\x00\x00',  # 4 reserved bytes
        )

    def read_file_header(self):
        """Read and return (network, start_height, header_count)."""
        with open(self.path, 'rb') as fd:
            buf = fd.read(ARCHIVE_FILE_HEADER_SIZE)
            if len(buf) < ARCHIVE_FILE_HEADER_SIZE:
                raise HeaderArchiveFormatError(
                    "Archive file too short to contain a file header: %s" % self.path)

            magic, ver_maj, ver_min, network_id, _reserved1, start_height, _reserved2 = \
                struct.unpack('<4sBBBBI4s', buf)

            if magic != ARCHIVE_MAGIC:
                raise HeaderArchiveFormatError(
                    "Archive magic mismatch: got %r, expected %r" % (magic, ARCHIVE_MAGIC))

            if ver_maj != ARCHIVE_VERSION_MAJOR:
                raise HeaderArchiveFormatError(
                    "Unsupported archive version: %d.%d (this client supports %d.x)" % (
                        ver_maj, ver_min, ARCHIVE_VERSION_MAJOR))

            if network_id not in NETWORK_ID_TO_NAME:
                raise HeaderArchiveFormatError(
                    "Unknown network ID in archive: %d" % network_id)

            file_size = os.path.getsize(self.path)
            body_size = file_size - ARCHIVE_FILE_HEADER_SIZE
            if body_size % BLOCK_HEADER_SIZE != 0:
                raise HeaderArchiveFormatError(
                    "Archive body size %d is not a multiple of %d" % (
                        body_size, BLOCK_HEADER_SIZE))

            header_count = body_size // BLOCK_HEADER_SIZE
            return NETWORK_ID_TO_NAME[network_id], start_height, header_count

    def get_header_at_height(self, height):
        """Return the bitcoin.core.CBlockHeader at this height.

        Raises IndexError if the height is outside the archive's range.
        """
        _network, start_height, header_count = self.read_file_header()
        end_height = start_height + header_count - 1

        if height < start_height or height > end_height:
            raise IndexError(
                "Height %d outside archive range %d-%d" % (height, start_height, end_height))

        offset = ARCHIVE_FILE_HEADER_SIZE + (height - start_height) * BLOCK_HEADER_SIZE
        with open(self.path, 'rb') as fd:
            fd.seek(offset)
            raw = fd.read(BLOCK_HEADER_SIZE)
            if len(raw) != BLOCK_HEADER_SIZE:
                raise HeaderArchiveFormatError(
                    "Short read at offset %d: got %d bytes, expected %d" % (
                        offset, len(raw), BLOCK_HEADER_SIZE))
            return bitcoin.core.CBlockHeader.deserialize(raw)

    def append_header(self, header):
        """Append a single header, validating prev-hash continuity and PoW.

        Raises HeaderArchiveChainError on validation failure.
        """
        network, start_height, header_count = self.read_file_header()
        next_height = start_height + header_count

        # Chain continuity: header's prev_block_hash must match the previously-
        # stored header's hash. Skip the check if this is the first header.
        if header_count > 0:
            prev_header = self.get_header_at_height(next_height - 1)
            if header.hashPrevBlock != prev_header.GetHash():
                raise HeaderArchiveChainError(
                    "Header at height %d does not chain to height %d: "
                    "prev_block_hash=%s, expected=%s" % (
                        next_height, next_height - 1,
                        header.hashPrevBlock.hex(), prev_header.GetHash().hex()))

        # Proof of work: hash(header) must satisfy the difficulty target
        # claimed in the header itself. This does NOT validate that the
        # nBits value is correct relative to the difficulty-adjustment
        # algorithm (which would require knowledge of the previous 2016
        # blocks); the fetcher's quorum logic provides that protection.
        #
        # CheckProofOfWork raises on failure and returns None on success.
        try:
            bitcoin.core.CheckProofOfWork(header.GetHash(), header.nBits)
        except bitcoin.core.CheckProofOfWorkError as exp:
            raise HeaderArchiveChainError(
                "Header at height %d fails proof-of-work check: %s" % (next_height, exp))

        with open(self.path, 'ab') as fd:
            fd.write(header.serialize())

    def append_headers(self, headers):
        """Append multiple headers in order, validating each."""
        for h in headers:
            self.append_header(h)

    def info(self):
        """Return a dict summarizing the archive."""
        network, start_height, header_count = self.read_file_header()
        return {
            'path': self.path,
            'network': network,
            'start_height': start_height,
            'header_count': header_count,
            'end_height': start_height + header_count - 1 if header_count > 0 else None,
            'file_size': os.path.getsize(self.path),
        }


class BlockHeaderSource:
    """Abstract source of Bitcoin block headers for OTS verification."""

    def get_header_at_height(self, height):
        """Return a bitcoin.core.CBlockHeader at this height.

        Raises IndexError if the height is not available.
        """
        raise NotImplementedError

    def get_block_count(self):
        """Return the highest known block height, if knowable.

        Some sources (e.g., a finite archive) may not have a well-defined
        notion of "the chain tip"; those should return the highest height
        they have available.
        """
        raise NotImplementedError


class BitcoinNodeHeaderSource(BlockHeaderSource):
    """Block header source backed by a python-bitcoinlib RPC proxy.

    Preserves the existing pre-2026 verify behavior: connect to a local
    Bitcoin Core node and fetch headers via JSON-RPC.
    """

    def __init__(self, proxy):
        self.proxy = proxy

    def get_header_at_height(self, height):
        block_count = self.proxy.getblockcount()
        if height > block_count:
            raise IndexError(
                "Bitcoin block height %d not found; %d is highest known block" % (
                    height, block_count))
        blockhash = self.proxy.getblockhash(height)
        return self.proxy.getblockheader(blockhash)

    def get_block_count(self):
        return self.proxy.getblockcount()


class LocalArchiveHeaderSource(BlockHeaderSource):
    """Block header source backed by a local on-disk header archive."""

    def __init__(self, archive):
        self.archive = archive

    def get_header_at_height(self, height):
        return self.archive.get_header_at_height(height)

    def get_block_count(self):
        _network, start_height, header_count = self.archive.read_file_header()
        if header_count == 0:
            return 0
        return start_height + header_count - 1


class EsploraHeaderFetcher:
    """Fetch Bitcoin block headers from an Esplora-compatible HTTP API.

    Used as a source for HeaderFetcher. Speaks the de facto Esplora API
    (blockstream.info, mempool.space, etc.):

        GET /block-height/<N>   -> blockhash (hex, big-endian display order)
        GET /block/<hash>/raw   -> first 80 bytes are the block header

    Note: Esplora's /block/<hash>/header endpoint exists on some deployments
    but not all; the /raw endpoint plus a 80-byte read is more portable.
    """

    USER_AGENT = "OpenTimestamps-Client headers-fetcher"

    def __init__(self, base_url, timeout=10):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout

    def _http_get(self, path):
        req = urllib.request.Request(self.base_url + path,
                                     headers={'User-Agent': self.USER_AGENT})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return resp.read()

    def get_blockhash_at_height(self, height):
        """Return the block hash (bytes, internal byte order) at this height."""
        raw = self._http_get('/block-height/%d' % height)
        hex_display = raw.decode('ascii').strip()
        # Esplora returns hashes in display (big-endian) order; convert to
        # internal (little-endian) order to match python-bitcoinlib.
        return bytes.fromhex(hex_display)[::-1]

    def get_header_at_height(self, height):
        """Return a CBlockHeader for the block at this height."""
        block_hash = self.get_blockhash_at_height(height)
        hex_display = block_hash[::-1].hex()
        raw_block = self._http_get('/block/%s/raw' % hex_display)
        if len(raw_block) < BLOCK_HEADER_SIZE:
            raise HeaderArchiveError(
                "Esplora returned %d bytes for /block/%s/raw, expected at least %d" % (
                    len(raw_block), hex_display, BLOCK_HEADER_SIZE))
        return bitcoin.core.CBlockHeader.deserialize(raw_block[:BLOCK_HEADER_SIZE])

    def get_tip_height(self):
        """Return the current chain tip height according to this source."""
        raw = self._http_get('/blocks/tip/height')
        return int(raw.decode('ascii').strip())


class HeaderFetcher:
    """Fetch block headers from one or more sources with optional quorum.

    Given a list of source objects that each implement
    `get_header_at_height(height) -> CBlockHeader`, query all sources
    and require quorum agreement on the serialized header bytes before
    returning. PoW and prev-hash continuity checks are the responsibility
    of HeaderArchive.append_header.
    """

    def __init__(self, sources, quorum=None):
        if not sources:
            raise ValueError("HeaderFetcher requires at least one source")
        self.sources = list(sources)
        # Default quorum: majority of sources (rounded up).
        if quorum is None:
            quorum = (len(self.sources) + 1) // 2
        if quorum < 1 or quorum > len(self.sources):
            raise ValueError("Quorum %d outside valid range 1..%d" % (
                quorum, len(self.sources)))
        self.quorum = quorum

    def fetch_header(self, height):
        """Fetch a header at the given height, requiring quorum agreement.

        Raises HeaderArchiveError if quorum cannot be reached.
        """
        results_by_serialized = {}
        errors = []
        for source in self.sources:
            try:
                header = source.get_header_at_height(height)
                key = bytes(header.serialize())
                results_by_serialized.setdefault(key, []).append(source)
            except Exception as exp:
                errors.append((source, exp))
                logging.debug("Source %r failed for height %d: %s" % (source, height, exp))

        if not results_by_serialized:
            raise HeaderArchiveError(
                "No source returned a header for height %d (errors: %s)" % (
                    height, errors))

        # Pick the serialized form with the most agreeing sources.
        best_serialized, best_sources = max(
            results_by_serialized.items(), key=lambda kv: len(kv[1]))

        if len(best_sources) < self.quorum:
            raise HeaderArchiveError(
                "Quorum %d not reached for height %d: best agreement was %d source(s) "
                "(total responses: %d; errors: %d)" % (
                    self.quorum, height, len(best_sources),
                    sum(len(v) for v in results_by_serialized.values()),
                    len(errors)))

        return bitcoin.core.CBlockHeader.deserialize(best_serialized)


def make_default_esplora_sources(network):
    """Return a list of default EsploraHeaderFetcher sources for a network.

    Mainnet has multiple independent Esplora deployments; testnet and
    regtest have fewer (regtest has none, by definition).
    """
    if network == 'mainnet':
        return [
            EsploraHeaderFetcher('https://blockstream.info/api'),
            EsploraHeaderFetcher('https://mempool.space/api'),
            EsploraHeaderFetcher('https://mempool.emzy.de/api'),
        ]
    elif network == 'testnet':
        return [
            EsploraHeaderFetcher('https://blockstream.info/testnet/api'),
            EsploraHeaderFetcher('https://mempool.space/testnet/api'),
        ]
    elif network == 'regtest':
        return []
    else:
        raise ValueError("Unknown network: %s" % network)


# vim:syntax=python filetype=python
