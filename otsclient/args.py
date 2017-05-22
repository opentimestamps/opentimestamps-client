# Copyright (C) 2016 The OpenTimestamps developers
#
# This file is part of the OpenTimestamps Client.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of the OpenTimestamps Client, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import argparse
import bitcoin
import logging
import os
import sys
import socket

import opentimestamps.calendar

import otsclient
import otsclient.cache
import otsclient.cmds

DEFAULT_WHITELIST = ['https://*.calendar.opentimestamps.org', 'https://*.calendar.eternitywall.com']


def make_common_options_arg_parser():
    parser = argparse.ArgumentParser(description="OpenTimestamps client.")
    parser.add_argument('--version', action='version', version='v%s' % otsclient.__version__)

    parser.add_argument("-q", "--quiet", action="count", default=0,
                        help="Be more quiet.")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Be more verbose. Both -v and -q may be used multiple times.")

    whitelist_group  = parser.add_mutually_exclusive_group()
    whitelist_group.add_argument('-l', '--whitelist', metavar='URL', action='append', type=str,
                                 default=[],
                                 help='Whitelist a remote calendar. If no whitelist is specified, %s is whitelisted by default.' % DEFAULT_WHITELIST)
    whitelist_group.add_argument('--no-remote-calendars', dest='whitelist', action='store_const',
                                 const=None,
                                 default=[],
                                 help='Prevent any remote calendar from being contacted.')

    cache_group  = parser.add_mutually_exclusive_group()
    cache_group.add_argument("--cache", action="store", type=str,
                             dest='cache_path',
                             default='~/.cache/ots',
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
                        help="Bitcoin node URL to connect to (defaults to local "
                             "configuration)")

    return parser

def handle_common_options(args, parser):
    args.parser = parser
    args.verbosity = args.verbose - args.quiet

    if args.cache_path is not None:
        args.cache_path = os.path.normpath(os.path.expanduser(args.cache_path))
    args.cache = otsclient.cache.TimestampCache(args.cache_path)

    if args.whitelist is not None:
        if not args.whitelist:
            args.whitelist = DEFAULT_WHITELIST

        whitelist = opentimestamps.calendar.UrlWhitelist()
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
                              help="Commitments are sent to remote calendars,"
                                   "in the event of timeout the timestamp is considered "
                                   "done if at least M calendars replied. "
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

    parser_verify.add_argument('timestamp_fd', metavar='TIMESTAMP', type=argparse.FileType('rb'),
                               help='Timestamp filename')

    # ----- info -----
    parser_info = subparsers.add_parser('info', aliases=['i'],
                                        help='Show information on a timestamp')
    parser_info.add_argument('file', metavar='FILE', type=argparse.FileType('rb'),
                             help='Filename')



    parser_stamp.set_defaults(cmd_func=otsclient.cmds.stamp_command)
    parser_upgrade.set_defaults(cmd_func=otsclient.cmds.upgrade_command)
    parser_verify.set_defaults(cmd_func=otsclient.cmds.verify_command)
    parser_info.set_defaults(cmd_func=otsclient.cmds.info_command)

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
