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

import hashlib
import io
import logging
import os
import socket
import struct
import urllib.request

import bitcoin
import bitcoin.core
import bitcoin.messages
import bitcoin.net


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

            # Stat the already-open descriptor rather than re-resolving the
            # path, so the size describes the same inode we just read the
            # header bytes from even if the path is concurrently replaced.
            file_size = os.fstat(fd.fileno()).st_size
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


# Sparse on-disk cache of (height, header) pairs.
#
# Unlike HeaderArchive, which stores a contiguous range from start_height
# onwards, VerifyCache stores arbitrary individual heights. It exists to
# back the auto-fetch path used by `ots verify` when no Bitcoin node and
# no explicit --headers archive are configured: each fetched header is
# cached so subsequent verifications of the same proof are network-free.
#
# Format:
#
#   bytes  | field        | description
#   -------+--------------+----------------------------------------------
#   0..3   | magic        | 'OTSV' (4 ASCII bytes)
#   4      | version_major| currently 1
#   5      | version_minor| currently 0
#   6      | network      | 0=mainnet, 1=testnet, 2=regtest
#   7      | reserved     | 0x00
#   8..15  | reserved     | 8 bytes, zero
#
# Followed by N records of 84 bytes each:
#
#   bytes  | field         | description
#   -------+---------------+----------------------------------------------
#   0..3   | height        | uint32 little-endian
#   4..83  | header_bytes  | 80-byte serialized block header
#
# Records may appear in any order, and duplicates are tolerated (readers
# return the first matching record). The file is append-only.

VERIFY_CACHE_MAGIC = b'OTSV'
VERIFY_CACHE_VERSION_MAJOR = 1
VERIFY_CACHE_VERSION_MINOR = 0
VERIFY_CACHE_FILE_HEADER_SIZE = 16
VERIFY_CACHE_RECORD_SIZE = 4 + BLOCK_HEADER_SIZE


class VerifyCache:
    """Sparse on-disk cache of (height, CBlockHeader) pairs for auto-fetch.

    Backs AutoFetchHeaderSource, which fills it lazily as `ots verify`
    walks a timestamp proof. Each cached entry is PoW-validated at write
    time, so a tampered cache file fails PoW on read.
    """

    def __init__(self, path):
        self.path = path

    def exists(self):
        return os.path.isfile(self.path)

    def create(self, network):
        """Create a new empty verify cache for the given network.

        Writes the 16-byte file header and nothing else. Raises
        HeaderArchiveError if the file already exists.
        """
        if os.path.exists(self.path):
            raise HeaderArchiveError("Verify cache file already exists: %s" % self.path)
        if network not in NETWORK_NAME_TO_ID:
            raise HeaderArchiveError("Unknown network: %s" % network)
        os.makedirs(os.path.dirname(self.path) or '.', exist_ok=True)
        with open(self.path, 'wb') as fd:
            fd.write(struct.pack(
                '<4sBBBB8s',
                VERIFY_CACHE_MAGIC,
                VERIFY_CACHE_VERSION_MAJOR,
                VERIFY_CACHE_VERSION_MINOR,
                NETWORK_NAME_TO_ID[network],
                0,  # reserved byte
                b'\x00' * 8,  # 8 reserved bytes
            ))

    def read_file_header(self):
        """Return (network_name, record_count)."""
        with open(self.path, 'rb') as fd:
            buf = fd.read(VERIFY_CACHE_FILE_HEADER_SIZE)
            if len(buf) < VERIFY_CACHE_FILE_HEADER_SIZE:
                raise HeaderArchiveFormatError(
                    "Verify cache too short to contain a file header: %s" % self.path)
            magic, ver_maj, ver_min, network_id, _reserved1, _reserved2 = \
                struct.unpack('<4sBBBB8s', buf)
            if magic != VERIFY_CACHE_MAGIC:
                raise HeaderArchiveFormatError(
                    "Verify cache magic mismatch: got %r, expected %r" % (
                        magic, VERIFY_CACHE_MAGIC))
            if ver_maj != VERIFY_CACHE_VERSION_MAJOR:
                raise HeaderArchiveFormatError(
                    "Unsupported verify cache version: %d.%d (this client supports %d.x)" % (
                        ver_maj, ver_min, VERIFY_CACHE_VERSION_MAJOR))
            if network_id not in NETWORK_ID_TO_NAME:
                raise HeaderArchiveFormatError(
                    "Unknown network ID in verify cache: %d" % network_id)
            # Same inode-consistency reasoning as HeaderArchive.read_file_header.
            file_size = os.fstat(fd.fileno()).st_size
            body_size = file_size - VERIFY_CACHE_FILE_HEADER_SIZE
            if body_size % VERIFY_CACHE_RECORD_SIZE != 0:
                raise HeaderArchiveFormatError(
                    "Verify cache body size %d is not a multiple of %d" % (
                        body_size, VERIFY_CACHE_RECORD_SIZE))
            record_count = body_size // VERIFY_CACHE_RECORD_SIZE
            return NETWORK_ID_TO_NAME[network_id], record_count

    def iter_records(self):
        """Yield (height, CBlockHeader) for each cached record, in file order."""
        self.read_file_header()  # validate format before iterating
        with open(self.path, 'rb') as fd:
            fd.seek(VERIFY_CACHE_FILE_HEADER_SIZE)
            while True:
                buf = fd.read(VERIFY_CACHE_RECORD_SIZE)
                if not buf:
                    return
                if len(buf) < VERIFY_CACHE_RECORD_SIZE:
                    raise HeaderArchiveFormatError(
                        "Truncated record in verify cache: %s" % self.path)
                height = struct.unpack('<I', buf[:4])[0]
                header = bitcoin.core.CBlockHeader.deserialize(buf[4:])
                yield height, header

    def get(self, height):
        """Return the cached CBlockHeader at this height, or None if absent."""
        for h, header in self.iter_records():
            if h == height:
                return header
        return None

    def add(self, height, header):
        """Append a (height, header) record, validating proof-of-work.

        Does not enforce chain-continuity, since cache entries are sparse.
        The trust signal for AutoFetchHeaderSource is fetcher-level quorum
        agreement plus this PoW check.

        Raises HeaderArchiveChainError if PoW validation fails.
        """
        try:
            bitcoin.core.CheckProofOfWork(header.GetHash(), header.nBits)
        except bitcoin.core.CheckProofOfWorkError as exp:
            raise HeaderArchiveChainError(
                "Header at height %d fails proof-of-work check: %s" % (height, exp))
        with open(self.path, 'ab') as fd:
            fd.write(struct.pack('<I', height) + header.serialize())


class LocalVerifyCacheHeaderSource(BlockHeaderSource):
    """BlockHeaderSource backed by a sparse VerifyCache file.

    Symmetric with LocalArchiveHeaderSource (which wraps the dense
    HeaderArchive format) so a single --headers PATH can transparently
    read either: see detect_archive_format() and the dispatch in
    args.get_header_source().
    """

    def __init__(self, cache):
        self.cache = cache

    def get_header_at_height(self, height):
        header = self.cache.get(height)
        if header is None:
            raise IndexError(
                "Height %d not found in verify cache %s" % (height, self.cache.path))
        return header

    def get_block_count(self):
        # VerifyCache is sparse: "tip" isn't meaningful. Return the
        # highest cached height as a best-effort answer.
        highest = -1
        for height, _header in self.cache.iter_records():
            if height > highest:
                highest = height
        return highest if highest >= 0 else 0


def detect_archive_format(path):
    """Read the first 4 bytes of `path` and return the magic.

    Returns one of ARCHIVE_MAGIC, VERIFY_CACHE_MAGIC, or the raw bytes
    if neither matches. Callers can dispatch on this to read either
    format from the same --headers PATH.
    """
    with open(path, 'rb') as fd:
        magic = fd.read(4)
    return magic


def build_sidecar_from_heights(heights, output_path, network, fetcher,
                               force=False, log=True):
    """Build a sparse-archive sidecar covering the given Bitcoin block heights.

    Fetch each height's header via `fetcher` (quorum across HTTP sources),
    validate PoW, and write the (height, header) records to a new
    VerifyCache at `output_path`. The resulting file is a self-contained
    sidecar that a recipient can pass to `ots verify --headers <path>`
    to verify offline, without an OTS installation, a Bitcoin node, or
    network access.

    This is a pure cache-building primitive: callers (e.g., the CLI
    handler in cmds.py) are responsible for sourcing the heights from
    .ots files (or wherever else). Keeping .ots parsing out of headers.py
    avoids pulling in opentimestamps.core dependencies here.

    Raises HeaderArchiveError on fetch failure, quorum failure, or if
    the output path already exists and `force` is False.
    """
    if os.path.exists(output_path) and not force:
        raise HeaderArchiveError(
            "Output path already exists: %s "
            "(pass --force to overwrite)" % output_path)

    if not heights:
        raise HeaderArchiveError("No heights provided; nothing to build")

    # Order heights for predictable on-disk record order and logging.
    heights = sorted(set(heights))
    if log:
        logging.info(
            "Building sidecar for %d Bitcoin attestation height(s): %s" % (
                len(heights), ', '.join(str(h) for h in heights)))

    # If overwriting, remove the old file so VerifyCache.create() succeeds.
    if os.path.exists(output_path):
        os.unlink(output_path)
    cache = VerifyCache(output_path)
    cache.create(network)
    for height in heights:
        if log:
            logging.info("Fetching block %d header..." % height)
        header = fetcher.fetch_header(height)
        # VerifyCache.add validates PoW; trust signal is fetcher quorum
        # plus that per-record PoW check.
        cache.add(height, header)

    return {
        'path': output_path,
        'network': network,
        'heights': heights,
        'header_count': len(heights),
    }


class AutoFetchHeaderSource(BlockHeaderSource):
    """Block header source that fetches lazily from public HTTP sources.

    The default for `ots verify` when no Bitcoin node and no explicit
    --headers archive are configured. Each height looked up is fetched
    once (with quorum agreement across multiple sources) and cached on
    disk so subsequent verifications of the same proof are network-free.

    Trust signal: quorum agreement across the fetcher's sources, plus
    per-header proof-of-work validation. A tampered cache file would
    simply fail PoW on read; a malicious source either fails quorum or
    fails PoW.
    """

    def __init__(self, cache, fetcher, network, log=True):
        self.cache = cache  # VerifyCache or None (caching disabled)
        self.fetcher = fetcher
        self.network = network
        self.log = log

    def _ensure_cache_for_network(self):
        """Create the cache file if absent, or validate its network if present."""
        if self.cache is None:
            return
        if self.cache.exists():
            cache_network, _count = self.cache.read_file_header()
            if cache_network != self.network:
                raise HeaderArchiveNetworkMismatch(
                    "Verify cache network %r does not match selected network %r" % (
                        cache_network, self.network))
        else:
            self.cache.create(self.network)

    def get_header_at_height(self, height):
        if self.cache is not None and self.cache.exists():
            cache_network, _count = self.cache.read_file_header()
            if cache_network != self.network:
                raise HeaderArchiveNetworkMismatch(
                    "Verify cache network %r does not match selected network %r" % (
                        cache_network, self.network))
            cached = self.cache.get(height)
            if cached is not None:
                logging.debug("Verify cache hit for height %d" % height)
                return cached

        if self.log:
            logging.info("Fetching block %d header from public sources..." % height)
        header = self.fetcher.fetch_header(height)
        # HeaderFetcher does quorum agreement but does not check PoW.
        # We check it here so cached entries are always trustworthy.
        try:
            bitcoin.core.CheckProofOfWork(header.GetHash(), header.nBits)
        except bitcoin.core.CheckProofOfWorkError as exp:
            raise HeaderArchiveChainError(
                "Fetched header at height %d fails proof-of-work check: %s" % (
                    height, exp))

        if self.cache is not None:
            self._ensure_cache_for_network()
            self.cache.add(height, header)
        return header

    def get_block_count(self):
        """Query the underlying sources for the chain tip."""
        for source in self.fetcher.sources:
            try:
                return source.get_tip_height()
            except Exception as exp:
                logging.debug("Source %r failed to return tip height: %s" % (source, exp))
        raise HeaderArchiveError("No source returned a chain-tip height")


# Bitcoin P2P getheaders SPV-style fetcher
#
# The HTTP-explorer fetcher above is fine for small ranges (one or a few
# headers around an OTS attestation). For bulk fetches -- the entire chain
# or large ranges -- it's the wrong transport: per-block HTTP calls are
# rate-limited and slow.
#
# Bitcoin's P2P `getheaders` message returns up to 2000 headers per round
# trip. Full-chain fetch is ~475 round trips (a couple of minutes against a
# typical peer) instead of millions of HTTP calls (days, plus rate limits).
# This is the canonical SPV bulk-header path -- used by Electrum, BitcoinJ,
# every wallet.
#
# python-bitcoinlib provides the message types (msg_version, msg_verack,
# msg_getheaders, msg_headers); we add the connection loop and a small
# workaround for one quirk: the headers wire format appends a 0x00 varint
# after each 80-byte header (transaction count, always zero in this
# context), and python-bitcoinlib's CBlockHeader.stream_deserialize doesn't
# consume that trailing byte. We intercept the `headers` command at the
# framing layer and parse the body ourselves so the trailing byte is
# correctly skipped.

P2P_DEFAULT_TIMEOUT = 30
P2P_MESSAGE_HEADER_SIZE = 24  # magic(4) + command(12) + length(4) + checksum(4)


class P2PFetcherError(HeaderArchiveError):
    """Base class for Bitcoin P2P fetcher errors."""


class P2PHandshakeError(P2PFetcherError):
    """Failed to complete the version/verack handshake with a peer."""


class P2PProtocolError(P2PFetcherError):
    """Received an unexpected, malformed, or out-of-spec message from a peer."""


def _read_exact(sock_file, n):
    """Read exactly n bytes from a file-like, raising on short reads.

    socket.makefile() with default buffering loops on read() until n bytes
    are available, but the loop terminates early on EOF -- which is what we
    want to detect explicitly here.
    """
    buf = sock_file.read(n)
    if len(buf) < n:
        raise EOFError("Expected %d bytes, got %d" % (n, len(buf)))
    return buf


def _read_p2p_message(sock_file):
    """Read one P2P message from a socket-as-file, returning (command, body).

    Generic message framing: magic + command + length + checksum + body.
    Returns the command bytes (e.g. b'headers') and the body bytes;
    callers are responsible for parsing the body according to command.

    Raises P2PProtocolError on a bad magic or checksum.
    """
    header = _read_exact(sock_file, P2P_MESSAGE_HEADER_SIZE)
    if header[:4] != bitcoin.params.MESSAGE_START:
        raise P2PProtocolError("Bad message magic %s, expected %s" % (
            header[:4].hex(), bitcoin.params.MESSAGE_START.hex()))
    command = header[4:16].rstrip(b'\x00')
    body_len = struct.unpack(b'<I', header[16:20])[0]
    checksum = header[20:24]
    body = _read_exact(sock_file, body_len)
    expected_checksum = hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    if checksum != expected_checksum:
        raise P2PProtocolError("Bad checksum on '%s' message" % command.decode('ascii', 'replace'))
    return command, body


def _parse_headers_body(body):
    """Parse the body of a P2P 'headers' message, returning a list of CBlockHeader.

    Each entry in the wire format is 80 bytes of canonical block header
    followed by a single 0x00 byte (the transaction-count varint, always
    zero here since this is a header-only message).
    """
    f = io.BytesIO(body)
    count = bitcoin.core.VarIntSerializer.stream_deserialize(f)
    out = []
    for _ in range(count):
        header_bytes = f.read(80)
        if len(header_bytes) < 80:
            raise P2PProtocolError("Truncated header in headers message")
        header = bitcoin.core.CBlockHeader.deserialize(header_bytes)
        # Consume and discard the trailing transaction-count varint.
        bitcoin.core.VarIntSerializer.stream_deserialize(f)
        out.append(header)
    return out


def _send_p2p_message(sock, msg):
    """Serialize a python-bitcoinlib MsgSerializable and send it to a socket.

    `MsgSerializable.to_bytes()` already produces the fully-framed
    message (magic + command + length + checksum + body).
    """
    sock.sendall(msg.to_bytes())


def discover_p2p_peers_via_dns(network='mainnet', limit=20):
    """Resolve the network's DNS seeds to a list of (host, port) tuples.

    Returns at most `limit` peers, drawn round-robin across seeds so a
    single seed's failure doesn't dominate. Failed seeds are silently
    skipped; if all seeds fail, returns an empty list and the caller
    should fall back to user-provided peers.
    """
    seeds = [hostname for (_label, hostname) in bitcoin.params.DNS_SEEDS]
    port = bitcoin.params.DEFAULT_PORT
    per_seed = []
    for seed in seeds:
        addrs = []
        try:
            for info in socket.getaddrinfo(seed, port, type=socket.SOCK_STREAM):
                addrs.append((info[4][0], port))
        except socket.gaierror as exp:
            logging.debug("DNS seed %s failed: %s" % (seed, exp))
        per_seed.append(addrs)

    # Round-robin across seeds so we don't get stuck on a slow/bad one.
    out = []
    while len(out) < limit:
        added = False
        for addrs in per_seed:
            if addrs:
                out.append(addrs.pop(0))
                added = True
                if len(out) >= limit:
                    break
        if not added:
            break
    return out


class _P2PPeerSession:
    """A short-lived Bitcoin P2P session for fetching headers from one peer.

    Use as a context manager:

        with _P2PPeerSession(host, port) as session:
            headers = session.request_headers(locator_hash)
            ...

    The session handles the version/verack handshake on entry and closes
    the socket on exit. Slow/unresponsive peers are bounded by a per-call
    socket timeout (default 30 seconds).
    """

    def __init__(self, host, port, timeout=P2P_DEFAULT_TIMEOUT):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.sock_file = None

    def __enter__(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        # Default buffering ensures read(n) loops until n bytes are available
        # (or EOF). Headers messages can be ~162 KB and need that loop.
        self.sock_file = self.sock.makefile('rb')
        try:
            self._handshake()
        except Exception:
            self._close()
            raise
        return self

    def __exit__(self, *exc):
        self._close()

    def _close(self):
        for resource in (self.sock_file, self.sock):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    pass
        self.sock_file = None
        self.sock = None

    def _handshake(self):
        """Perform the version/verack handshake. Both directions exchange both messages."""
        _send_p2p_message(self.sock, bitcoin.messages.msg_version())
        got_version = False
        got_verack = False
        # Bound the handshake so a misbehaving peer can't keep us looping.
        for _ in range(20):
            command, body = _read_p2p_message(self.sock_file)
            if command == b'version':
                got_version = True
                _send_p2p_message(self.sock, bitcoin.messages.msg_verack())
            elif command == b'verack':
                got_verack = True
            # Other messages (alert, sendheaders, sendcmpct, etc.) are ignored.
            if got_version and got_verack:
                return
        raise P2PHandshakeError("Did not complete handshake with %s:%d" % (self.host, self.port))

    def request_headers(self, locator_hash, hashstop=None):
        """Send a getheaders request and return the resulting list of CBlockHeader.

        `locator_hash` is the bytes of the most recent block we have (in
        internal byte order, i.e. matching CBlockHeader.GetHash()). The
        peer will respond with up to 2000 headers starting from the block
        AFTER the one we name.

        If `hashstop` is None, the peer sends as many headers as it
        wishes (up to 2000); otherwise it stops at the named hash.

        Returns an empty list if the peer thinks we're already at its tip.
        Other unsolicited messages (ping, inv, addr) are handled or
        ignored while waiting for the headers response.
        """
        gh = bitcoin.messages.msg_getheaders()
        gh.locator.vHave = [locator_hash]
        if hashstop is not None:
            gh.hashstop = hashstop
        _send_p2p_message(self.sock, gh)

        # Bound the wait so a peer that just sends pings forever can't
        # deadlock us.
        for _ in range(50):
            command, body = _read_p2p_message(self.sock_file)
            if command == b'headers':
                return _parse_headers_body(body)
            elif command == b'ping':
                # Respond to keep the connection alive while we wait.
                pong = bitcoin.messages.msg_pong()
                pong.nonce = struct.unpack(b'<Q', body[:8])[0]
                _send_p2p_message(self.sock, pong)
            # Everything else (inv, addr, alert, getheaders from the peer,
            # etc.) is ignored -- we're only looking for our headers reply.
        raise P2PProtocolError("Did not receive headers response from %s:%d" % (
            self.host, self.port))


class BitcoinP2PHeaderFetcher:
    """Fetch Bitcoin block headers via the Bitcoin P2P protocol.

    Significantly faster than HTTP-explorer fetching for bulk operations:
    a single getheaders round trip returns up to 2000 headers, so the
    full chain since 2009 fetches in a couple of minutes against a
    responsive peer.

    Uses one peer at a time; on peer failure (connection refused, slow
    peer, malformed response, headers that fail PoW or chain-continuity
    validation), falls through to the next peer. PoW + prev-hash
    continuity is the trust anchor: a malicious peer can only feed us
    chains that fail PoW, which we catch and treat as cause to drop the
    peer.

    This fetcher only supports archives that begin at the genesis block
    (start_height == 0). Partial archives starting at a higher height
    require knowing the exact previous-block hash to construct the
    locator, which we don't have a portable source for; use the HTTP
    fetcher (EsploraHeaderFetcher) for those cases.
    """

    def __init__(self, network='mainnet', peers=None, timeout=P2P_DEFAULT_TIMEOUT,
                 dns_discovery_limit=20):
        self.network = network
        self._explicit_peers = list(peers) if peers else None
        self.timeout = timeout
        self.dns_discovery_limit = dns_discovery_limit

    def get_peers(self):
        """Return the list of (host, port) peers to try, in order."""
        if self._explicit_peers is not None:
            return list(self._explicit_peers)
        return discover_p2p_peers_via_dns(self.network, limit=self.dns_discovery_limit)

    def fetch_into(self, archive, until_height=None):
        """Fetch headers into the given archive, starting from where it left off.

        Connects to peers in turn; for each peer, requests batches of up
        to 2000 headers in a loop, validating each header via
        archive.append_header (which checks PoW and prev-hash continuity).

        If until_height is given, stops appending once that height is
        reached; otherwise continues until the peer reports we're at the
        chain tip (empty headers response).

        Returns the number of headers appended in this call.
        """
        _network, start_height, header_count = archive.read_file_header()
        if start_height != 0:
            raise P2PFetcherError(
                "P2P fetcher only supports archives starting at genesis (height 0); "
                "got start_height=%d. Use the HTTP fetcher for partial archives." % start_height)

        # Seed an empty archive with genesis so subsequent locators have
        # something to anchor to. Peers respond to a zero-hash locator by
        # sending headers starting at height 1, not at genesis.
        if header_count == 0:
            genesis = bitcoin.params.GENESIS_BLOCK
            if hasattr(genesis, 'get_header'):
                genesis = genesis.get_header()
            archive.append_header(genesis)
            logging.debug("Seeded empty archive with genesis (network=%s)" % self.network)

        peers = self.get_peers()
        if not peers:
            raise P2PFetcherError(
                "No Bitcoin P2P peers available "
                "(DNS seed discovery returned nothing; try --p2p-peer host[:port])")

        appended_total = 0
        for peer_host, peer_port in peers:
            try:
                with _P2PPeerSession(peer_host, peer_port, self.timeout) as session:
                    appended_from_this_peer = self._drain_peer(
                        session, archive, until_height)
                    appended_total += appended_from_this_peer
                    if appended_from_this_peer == 0:
                        # Peer says we're done (returned an empty headers list).
                        return appended_total
            except (socket.error, EOFError, P2PFetcherError) as exp:
                logging.debug("P2P peer %s:%d failed (appended=%d so far): %s" % (
                    peer_host, peer_port, appended_total, exp))
                continue

        if appended_total == 0:
            raise P2PFetcherError(
                "All %d peer(s) failed without appending any headers" % len(peers))
        return appended_total

    def _drain_peer(self, session, archive, until_height, log_every=5000):
        """Repeatedly request headers from one peer until done or it stops responding.

        Returns the number of headers appended via this peer in this call.
        Logs progress every `log_every` headers so a multi-minute bulk
        fetch isn't silent.
        """
        appended = 0
        next_log_at = log_every
        while True:
            _network, start_height, header_count = archive.read_file_header()
            tip_header = archive.get_header_at_height(start_height + header_count - 1)
            locator_hash = tip_header.GetHash()

            batch = session.request_headers(locator_hash)
            if not batch:
                # Peer believes we're at the chain tip.
                return appended

            for header in batch:
                if until_height is not None:
                    _net, sh, hc = archive.read_file_header()
                    if sh + hc - 1 >= until_height:
                        return appended
                try:
                    archive.append_header(header)
                    appended += 1
                except HeaderArchiveChainError as exp:
                    # A header that fails PoW or chain continuity means
                    # this peer is feeding us bad data. Stop with this peer;
                    # the outer loop will try the next one.
                    raise P2PProtocolError(
                        "Peer returned invalid header: %s" % exp)

                if appended >= next_log_at:
                    _net, sh, hc = archive.read_file_header()
                    logging.info("... fetched %d headers (at height %d)" % (
                        appended, sh + hc - 1))
                    next_log_at += log_every


# Bootstrap a header archive from a URL.
#
# `ots headers fetch --p2p` builds an archive in minutes; for users who'd
# rather not even spend the minutes, a prebuilt archive can be downloaded
# from any URL (GitHub Releases, IPFS, a friend's mirror, a magnet-extracted
# file via file://). The trust model is identical to a self-built archive:
# every header is validated against PoW + prev-hash continuity before the
# file is installed. The source URL doesn't have to be trusted -- the math
# is the trust signal. A tampered file fails validation; a benign mirror
# just speeds things up.

BOOTSTRAP_DEFAULT_TIMEOUT = 60
BOOTSTRAP_DOWNLOAD_CHUNK = 1024 * 1024  # 1 MB


def _walk_validate_archive(path, expected_network, partial_hint=None):
    """Open the archive at `path`, walk every header, verify PoW + continuity.

    Returns (network, start_height, header_count) on success. Raises
    HeaderArchiveError or subclass on any validation failure. `partial_hint`
    is appended to error messages so callers can point users at the
    preserved partial download.
    """
    archive = HeaderArchive(path)
    network, start_height, header_count = archive.read_file_header()
    if network != expected_network:
        suffix = " (partial preserved at %s)" % partial_hint if partial_hint else ""
        raise HeaderArchiveNetworkMismatch(
            "Archive network %r does not match expected %r%s" % (
                network, expected_network, suffix))

    if header_count == 0:
        return network, start_height, header_count

    with open(path, 'rb') as fd:
        fd.seek(ARCHIVE_FILE_HEADER_SIZE)
        prev_hash = None
        for i in range(header_count):
            height = start_height + i
            raw = fd.read(BLOCK_HEADER_SIZE)
            if len(raw) != BLOCK_HEADER_SIZE:
                suffix = " (partial preserved at %s)" % partial_hint if partial_hint else ""
                raise HeaderArchiveFormatError(
                    "Truncated header at height %d%s" % (height, suffix))
            header = bitcoin.core.CBlockHeader.deserialize(raw)
            try:
                bitcoin.core.CheckProofOfWork(header.GetHash(), header.nBits)
            except bitcoin.core.CheckProofOfWorkError as exp:
                suffix = " (partial preserved at %s)" % partial_hint if partial_hint else ""
                raise HeaderArchiveChainError(
                    "Header at height %d fails proof-of-work check: %s%s" % (
                        height, exp, suffix))
            if prev_hash is not None and header.hashPrevBlock != prev_hash:
                suffix = " (partial preserved at %s)" % partial_hint if partial_hint else ""
                raise HeaderArchiveChainError(
                    "Header at height %d does not chain to height %d: "
                    "prev_block_hash=%s, expected=%s%s" % (
                        height, height - 1,
                        header.hashPrevBlock.hex(), prev_hash.hex(), suffix))
            prev_hash = header.GetHash()

    return network, start_height, header_count


def bootstrap_archive_from_url(url, output_path, network,
                               expected_sha256=None,
                               timeout=BOOTSTRAP_DEFAULT_TIMEOUT,
                               progress_chunk_mb=10,
                               log=True):
    """Download a prebuilt header archive from `url` and install it locally.

    The downloaded file is written to `<output_path>.partial`, validated
    end-to-end (network match + PoW + prev-hash continuity for every
    header), then atomically renamed to `output_path`. If validation
    fails, the .partial file is left in place for inspection.

    The trust signal is the per-header math, not the source URL. So the
    URL can be any scheme `urllib.request` supports: http(s), file://,
    ftp, etc. The optional `expected_sha256` adds an integrity precheck
    against tampering or corruption-in-transit -- recommended when the
    URL points at a third-party host.

    Returns a dict {path, network, start_height, header_count, sha256}
    on success. Raises HeaderArchiveError (or subclass) on any failure.
    """
    if expected_sha256 is not None:
        expected_sha256 = expected_sha256.lower()

    partial_path = output_path + '.partial'
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

    if log:
        logging.info("Downloading header archive from %s" % url)

    progress_every = progress_chunk_mb * 1024 * 1024 if progress_chunk_mb else 0
    next_log_at = progress_every
    bytes_so_far = 0
    hasher = hashlib.sha256()

    try:
        req = urllib.request.Request(
            url, headers={'User-Agent': 'OpenTimestamps-Client headers-bootstrap'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            with open(partial_path, 'wb') as fd:
                while True:
                    buf = resp.read(BOOTSTRAP_DOWNLOAD_CHUNK)
                    if not buf:
                        break
                    fd.write(buf)
                    hasher.update(buf)
                    bytes_so_far += len(buf)
                    if progress_every and bytes_so_far >= next_log_at and log:
                        logging.info("... downloaded %d MB" % (
                            bytes_so_far // (1024 * 1024)))
                        next_log_at += progress_every
    except Exception as exp:
        raise HeaderArchiveError(
            "Failed to download from %s: %s (partial preserved at %s)" % (
                url, exp, partial_path))

    if log:
        logging.info("Downloaded %d bytes" % bytes_so_far)

    actual_sha256 = hasher.hexdigest()
    if expected_sha256 is not None and actual_sha256 != expected_sha256:
        raise HeaderArchiveError(
            "SHA-256 mismatch: expected %s, got %s "
            "(partial preserved at %s)" % (
                expected_sha256, actual_sha256, partial_path))

    if log:
        logging.info(
            "Validating archive (PoW + chain continuity, every header)...")
    try:
        network_in_file, start_height, header_count = _walk_validate_archive(
            partial_path, network, partial_hint=partial_path)
    except HeaderArchiveError:
        # Already includes "partial preserved at ..." in the message.
        raise

    if log:
        end_h = start_height + header_count - 1 if header_count > 0 else start_height
        logging.info("Validated %d header(s) (heights %d..%d)" % (
            header_count, start_height, end_h))

    # Atomic install. os.replace overwrites an existing file if present.
    os.replace(partial_path, output_path)
    if log:
        logging.info("Installed archive at %s" % output_path)

    return {
        'path': output_path,
        'network': network_in_file,
        'start_height': start_height,
        'header_count': header_count,
        'sha256': actual_sha256,
    }


# vim:syntax=python filetype=python
