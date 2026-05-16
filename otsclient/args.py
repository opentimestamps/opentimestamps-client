# Copyright (C) 2016-2018 The OpenTimestamps developers
#
# This file is part of the OpenTimestamps Client.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of the OpenTimestamps Client, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import appdirs
import argparse
import bitcoin
import logging
import os
import socket
import sys

import opentimestamps.calendar

import otsclient
import otsclient.cache
import otsclient.cmds
import otsclient.headers

APPDIRS = appdirs.AppDirs('ots','opentimestamps')

def make_common_options_arg_parser():
    parser = argparse.ArgumentParser(description="OpenTimestamps client.")
    parser.add_argument('--version', action='version', version='v%s' % otsclient.__version__)

    parser.add_argument("-q", "--quiet", action="count", default=0,
                        help="Be more quiet.")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Be more verbose. Both -v and -q may be used multiple times.")

    parser.add_argument('-l', '--whitelist', metavar='URL', action='append', type=str,
                        default=[],
                        help='Add a calendar to the whitelist.')
    parser.add_argument('--no-default-whitelist', action='store_true', default=False,
                        help='Do not load the default remote calendar whitelist; '
                             'contact only calendars that have been manually added with --whitelist')

    cache_group  = parser.add_mutually_exclusive_group()
    cache_group.add_argument("--cache", action="store", type=str,
                             dest='cache_path',
                             default=APPDIRS.user_cache_dir,
                             help="Location of the timestamp cache. Default: %(default)s")
    cache_group.add_argument("--no-cache", action="store_const", const=None,
                             dest='cache_path',
                             help="Disable the timestamp cache")

    btc_net_group  = parser.add_mutually_exclusive_group()
    btc_net_group.add_argument('--btc-testnet', dest='btc_net', action='store_const',
                               const='testnet', default='mainnet',
                               help='Use Bitcoin testnet rather than mainnet')
    btc_net_group.add_argument('--btc-regtest', dest='btc_net', action='store_const',
                               const='regtest',
                               help='Use Bitcoin regtest rather than mainnet')
    btc_net_group.add_argument('--no-bitcoin', dest='use_bitcoin', action='store_false',
                               default=True,
                               help='Disable Bitcoin entirely')

    parser.add_argument("-w", "--wait", action="store_true", default=False,
                        help="When creating, upgrading, or verifying "
                             "timestamps, wait until a complete timestamp "
                             "committed in the Bitcoin blockchain is available "
                             "instead of returning immediately.")
    parser.add_argument("--wait-interval", action="store", type=int, default=30,
                        help=argparse.SUPPRESS) # best if users don't change this and DoS attack the calendars...

    parser.add_argument("--socks5-proxy", type=str,
                        help="Route all traffic through a socks5 proxy, "
                              "including DNS queries. The default port is 1080. "
                              "Format: domain[:port] (e.g. localhost:9050)")

    parser.add_argument("--bitcoin-node", dest="bitcoin_node", type=str,
                        help="Bitcoin node URL to connect to. When set, verify "
                             "fetches block headers from this node instead of "
                             "auto-fetching from public block-explorer sources.")

    return parser

def handle_common_options(args, parser):
    args.parser = parser
    args.verbosity = args.verbose - args.quiet

    if args.cache_path is not None:
        args.cache_path = os.path.normpath(os.path.expanduser(args.cache_path))
    args.cache = otsclient.cache.TimestampCache(args.cache_path)

    whitelist = opentimestamps.calendar.UrlWhitelist()
    if not args.no_default_whitelist:
        whitelist.update(opentimestamps.calendar.DEFAULT_CALENDAR_WHITELIST)

    for url in args.whitelist:
        whitelist.add(url)

    args.whitelist = whitelist

    if args.socks5_proxy is not None:
        try:
            import socks
        except ImportError as exp:
            logging.error("Can not use SOCKS5 proxy: %s" % exp)
            sys.exit(1)

        e = args.socks5_proxy.split(':')
        s5_hostname = e[0]
        if len(e) > 1:
            if e[1].isdigit():
                s5_port = int(e[1])
            else:
                args.parser.error("SOCKS5 proxy port must be an integer; got %s" % e[1])
        else:
            s5_port = 1080

        socks.set_default_proxy(socks.SOCKS5,
                                s5_hostname,
                                s5_port)

        # Monkey patch socket to use SOCKS5 proxy
        socket.socket = socks.socksocket

        # This should prevent DNS leaks
        def create_connection(address, timeout=None, source_address=None):
            sock = socks.socksocket()
            sock.connect(address)
            return sock
        socket.create_connection = create_connection

    def setup_bitcoin():
        """Setup Bitcoin-related functionality

        Sets mainnet/testnet and returns a RPC proxy.
        """
        if args.btc_net == 'testnet':
           bitcoin.SelectParams('testnet')
        elif args.btc_net == 'regtest':
           bitcoin.SelectParams('regtest')
        elif args.btc_net == 'mainnet':
           bitcoin.SelectParams('mainnet')
        else:
            assert False

        try:
            return bitcoin.rpc.Proxy(service_url=args.bitcoin_node)
        except Exception as exp:
            logging.error("Could not connect to Bitcoin node: %s" % exp)
            sys.exit(1)

    args.setup_bitcoin = setup_bitcoin

    def _try_local_bitcoin_node():
        """Probe for a reachable local Bitcoin Core node.

        Returns a connected RPC proxy on success, or None if no local
        node is reachable. Bounded by a short timeout so it doesn't
        block verify when no node is running. Used by get_header_source
        to preserve the historical "I have a local node, just use it"
        behavior without requiring the user to pass --bitcoin-node.
        """
        if args.btc_net == 'testnet':
            bitcoin.SelectParams('testnet')
        elif args.btc_net == 'regtest':
            bitcoin.SelectParams('regtest')
        elif args.btc_net == 'mainnet':
            bitcoin.SelectParams('mainnet')
        else:
            assert False
        try:
            proxy = bitcoin.rpc.Proxy(service_url=None, timeout=2)
            proxy.getblockcount()  # cheap call to confirm reachability + auth
        except Exception as exp:
            logging.debug("No reachable local Bitcoin node: %s" % exp)
            return None
        return proxy

    def get_header_source():
        """Return a BlockHeaderSource appropriate for the current args.

        Precedence:
          1. --headers PATH         -> LocalArchiveHeaderSource
          2. --bitcoin-node URL     -> BitcoinNodeHeaderSource
          3. (default, no flags)    -> If a local Bitcoin Core node is
                                       reachable, use it (preserves the
                                       historical no-flag behavior for
                                       node operators). Otherwise
                                       AutoFetchHeaderSource (lazy HTTP
                                       fetch with quorum, cached in
                                       <cache_dir>/verify-cache-<net>.bin).

        Networks without default public sources (regtest) only have the
        Bitcoin-node path available in case 3.
        """
        headers_path = getattr(args, 'headers_path', None)
        if headers_path is not None:
            archive = otsclient.headers.HeaderArchive(headers_path)
            if not archive.exists():
                logging.error("Header archive not found: %s" % headers_path)
                sys.exit(1)
            try:
                archive_network, _start, _count = archive.read_file_header()
            except otsclient.headers.HeaderArchiveError as exp:
                logging.error("Header archive is invalid: %s" % exp)
                sys.exit(1)
            if archive_network != args.btc_net:
                logging.error(
                    "Header archive network %r does not match selected network %r" % (
                        archive_network, args.btc_net))
                sys.exit(1)
            return otsclient.headers.LocalArchiveHeaderSource(archive)

        if args.bitcoin_node is not None:
            proxy = setup_bitcoin()
            return otsclient.headers.BitcoinNodeHeaderSource(proxy)

        # Default: prefer a reachable local node (preserves historical
        # behavior for users who run `bitcoind`), else auto-fetch from
        # public Esplora-compatible sources with quorum and on-disk
        # caching.
        sources = otsclient.headers.make_default_esplora_sources(args.btc_net)
        if not sources:
            # No public sources for this network (e.g., regtest, which
            # has no public peers, DNS seeds, or block explorers by
            # design). Bitcoin node is the only path; let setup_bitcoin
            # produce its own clear error if no node is reachable.
            logging.info(
                "Network is %s; no public block-explorer sources available, "
                "falling back to Bitcoin node "
                "(use --headers PATH for fully offline verification)" % args.btc_net)
            proxy = setup_bitcoin()
            return otsclient.headers.BitcoinNodeHeaderSource(proxy)

        local_proxy = _try_local_bitcoin_node()
        if local_proxy is not None:
            logging.info(
                "Using local Bitcoin Core node for header lookup "
                "(pass --bitcoin-node URL to override, or use --headers PATH "
                "for an air-gapped archive)")
            return otsclient.headers.BitcoinNodeHeaderSource(local_proxy)

        if args.cache_path is None:
            # User passed --no-cache; disable verify-cache too.
            cache = None
        else:
            # One cache file per network so mainnet and testnet proofs
            # don't collide on the same path.
            cache_filename = 'verify-cache-%s.bin' % args.btc_net
            cache_path = os.path.join(args.cache_path, cache_filename)
            cache = otsclient.headers.VerifyCache(cache_path)

        fetcher = otsclient.headers.HeaderFetcher(sources)
        return otsclient.headers.AutoFetchHeaderSource(
            cache, fetcher, args.btc_net)

    args.get_header_source = get_header_source

    return args

def parse_ots_args(raw_args):
    parser = make_common_options_arg_parser()

    subparsers = parser.add_subparsers(title='Subcommands',
                                       description='All operations are done through subcommands:')

    # ----- stamp -----
    parser_stamp = subparsers.add_parser('stamp', aliases=['s'],
                                         help='Timestamp files')

    parser_stamp.add_argument('-c', '--calendar', metavar='URL', dest='calendar_urls', action='append', type=str,
                              default=[],
                              help='Create timestamp with the aid of a remote calendar. May be specified multiple times.')

    parser_stamp.add_argument('-b', '--btc-wallet', dest='use_btc_wallet', action='store_true',
                              help='Create timestamp locally with the local Bitcoin wallet.')

    parser_stamp.add_argument('files', metavar='FILE', type=argparse.FileType('rb'),
                              nargs='*',
                              help='Filename')

    parser_stamp.add_argument("--timeout", type=int, default=5,
                              help="Timeout before giving up on a calendar. "
                                   "Default: %(default)d")

    parser_stamp.add_argument("-m", type=int, default="2",
                              help="Consider the timestamp complete if at least M calendars reply prior to the timeout. "
                                   "Default: %(default)s")

    # ----- upgrade -----
    parser_upgrade = subparsers.add_parser('upgrade', aliases=['u'],
                                           help='Upgrade remote calendar timestamps to be locally verifiable')
    parser_upgrade.add_argument('-c', '--calendar', metavar='URL', dest='calendar_urls', action='append', type=str,
                                default=[],
                                help='Override calendars in timestamp')
    parser_upgrade.add_argument('-n', '--dry-run', action='store_true', default=False,
                                help='Perform a trial upgrade without modifying the existing timestamp.')
    parser_upgrade.add_argument('files', metavar='FILE', type=argparse.FileType('rb'),
                                nargs='+',
                                help='Existing timestamp(s); moved to FILE.bak')

    # ----- verify -----
    parser_verify = subparsers.add_parser('verify', aliases=['v'],
                                          help="Verify a timestamp")

    verify_target_group = parser_verify.add_mutually_exclusive_group()
    verify_target_group.add_argument('-f', metavar='FILE', dest='target_fd', type=argparse.FileType('rb'),
                                     default=None,
                                     help='Specify target file explicitly')
    verify_target_group.add_argument('-d', metavar='DIGEST', dest='hex_digest', type=str,
                                     default=None,
                                     help='Verify a (hex-encoded) digest rather than a file')

    parser_verify.add_argument('--headers', metavar='PATH', dest='headers_path', type=str,
                               default=None,
                               help='Verify using a local Bitcoin header archive (produced by '
                                    '`ots headers fetch`) instead of the default auto-fetch. '
                                    'Enables fully offline verification when the archive covers '
                                    'the attested block heights.')

    parser_verify.add_argument('timestamp_fd', metavar='TIMESTAMP', type=argparse.FileType('rb'),
                               help='Timestamp filename')

    # ----- headers -----
    parser_headers = subparsers.add_parser('headers',
                                           help='Manage local Bitcoin block header archive')
    headers_subparsers = parser_headers.add_subparsers(
        title='Subcommands',
        description='Header archive operations:')

    parser_headers_fetch = headers_subparsers.add_parser('fetch',
                                                         help='Fetch headers from public sources into a local archive')
    # The default is network-suffixed so that mainnet and testnet archives
    # live at distinct paths and don't trigger a network-mismatch error
    # when a user runs `ots headers fetch --btc-testnet` after building a
    # mainnet archive (or vice versa). Resolved at parse time against the
    # current --btc-* flag via set_defaults below.
    parser_headers_fetch.add_argument('--output', metavar='PATH', dest='headers_path', type=str,
                                      default=None,
                                      help='Path to the header archive file. '
                                           'Default: <cache_dir>/headers-<network>.bin')
    parser_headers_fetch.add_argument('--since-height', dest='since_height', type=int,
                                      default=None,
                                      help='Lowest block height to fetch. Default: continue from end of '
                                           'existing archive, or 0 if creating a new archive.')
    parser_headers_fetch.add_argument('--until-height', dest='until_height', type=int,
                                      default=None,
                                      help='Highest block height to fetch (inclusive). '
                                           'Default: current chain tip according to fetch sources.')
    parser_headers_fetch.add_argument('--source', metavar='URL', dest='source_urls', action='append',
                                      type=str, default=[],
                                      help='Esplora-compatible base URL to fetch from. May be specified '
                                           'multiple times. Defaults to a network-appropriate set of '
                                           'public sources if not given.')
    parser_headers_fetch.add_argument('--quorum', dest='quorum', type=int, default=None,
                                      help='Minimum number of agreeing sources required per header. '
                                           'Default: majority of provided sources (rounded up).')
    parser_headers_fetch.add_argument('--p2p', dest='use_p2p', action='store_true', default=False,
                                      help='Fetch via the Bitcoin P2P getheaders protocol instead of '
                                           'HTTP block explorers. Much faster for bulk fetches '
                                           '(up to 2000 headers per round trip). Uses DNS seeds for '
                                           'peer discovery by default. Mutually exclusive with --source.')
    parser_headers_fetch.add_argument('--p2p-peer', metavar='HOST[:PORT]', dest='p2p_peers',
                                      action='append', type=str, default=[],
                                      help='Specific Bitcoin P2P peer to connect to (may be repeated). '
                                           'Implies --p2p.')
    parser_headers_fetch.set_defaults(cmd_func=otsclient.cmds.headers_fetch_command)

    parser_headers_info = headers_subparsers.add_parser('info',
                                                        help='Show information about a local header archive')
    parser_headers_info.add_argument('archive_path', metavar='PATH', type=str,
                                     help='Path to the header archive file')
    parser_headers_info.set_defaults(cmd_func=otsclient.cmds.headers_info_command)

    parser_headers_bootstrap = headers_subparsers.add_parser(
        'bootstrap',
        help='Download a prebuilt header archive from a URL and install it locally')
    parser_headers_bootstrap.add_argument('url', metavar='URL', type=str,
        help='URL to download the archive from. Supports http(s)://, file://, '
             'and any other scheme urllib.request handles.')
    parser_headers_bootstrap.add_argument('--output', metavar='PATH',
        dest='headers_path', type=str, default=None,
        help='Where to install the validated archive. '
             'Default: <cache_dir>/headers-<network>.bin')
    parser_headers_bootstrap.add_argument('--sha256', metavar='HEX',
        dest='expected_sha256', type=str, default=None,
        help='Expected SHA-256 of the downloaded file (hex-encoded). '
             'Optional but recommended when the URL points at a third-party host.')
    parser_headers_bootstrap.add_argument('--force', dest='force_overwrite',
        action='store_true', default=False,
        help='Overwrite an existing archive at the output path. Without this, '
             'bootstrap refuses to clobber an existing file.')
    parser_headers_bootstrap.set_defaults(cmd_func=otsclient.cmds.headers_bootstrap_command)

    # ----- info -----
    parser_info = subparsers.add_parser('info', aliases=['i'],
                                        help='Show information on a timestamp')
    parser_info.add_argument('file', metavar='FILE', type=argparse.FileType('rb'),
                             help='Filename')

    # ----- prune -----
    parser_prune = subparsers.add_parser('prune', aliases=['p'],
                                         help='Prune timestamp')

    prune_verify_group = parser_prune.add_mutually_exclusive_group()
    prune_verify_group.add_argument('--verify', dest='attestations_to_verify', metavar='NOTARYSPEC', action='append',
                                    type=str, default=[],
                                    help='Verify attestations from a specified notary. May be specified multiple times.'
                                         ' Default btc.')
    prune_verify_group.add_argument('--no-verify', dest='no_verify', action='store_true', default=False,
                                    help='Do not verify any attestation.')

    parser_prune.add_argument('--discard', dest='attestations_to_discard', metavar='NOTARYSPEC', action='append',
                              type=str, default=[],
                              help='Discard attestations from a specified notary. May be specified multiple times. '
                                   'Default pending:*.')

    parser_prune.add_argument('timestamp_fd', metavar='TIMESTAMP', type=argparse.FileType('rb'),
                              help='Existing timestamp; moved to TIMESTAMP.bak')


    parser_stamp.set_defaults(cmd_func=otsclient.cmds.stamp_command)
    parser_upgrade.set_defaults(cmd_func=otsclient.cmds.upgrade_command)
    parser_verify.set_defaults(cmd_func=otsclient.cmds.verify_command)
    parser_info.set_defaults(cmd_func=otsclient.cmds.info_command)
    parser_prune.set_defaults(cmd_func=otsclient.cmds.prune_command)

    try:
        import git

        parser_git_extract = subparsers.add_parser('git-extract',
                                                   help='Extract timestamp for a single file from a timestamp git commit')
        parser_git_extract.add_argument('--annex', action='store_true',
                                        help='Enable git-annex symlink support')
        parser_git_extract.add_argument('path', metavar='PATH', type=str,
                                        help='Path to file, from root of the git repo')
        parser_git_extract.add_argument('timestamp_file', metavar='TIMESTAMP', type=argparse.FileType('xb'), nargs='?',
                                        help='Filename to write timestamp to. Default: PATH.ots')
        parser_git_extract.add_argument('commit', metavar='COMMIT', type=str, nargs='?',
                                        default='HEAD',
                                        help='Commit. Default: %(default)s')
        parser_git_extract.set_defaults(cmd_func=otsclient.cmds.git_extract_command)

    except ImportError:
        pass

    args = parser.parse_args(raw_args)
    args = handle_common_options(args, parser)

    return args
