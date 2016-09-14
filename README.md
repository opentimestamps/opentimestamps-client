# OpenTimestamps Client

Command-line tool to create and validate timestamp proofs with the
OpenTimestamps protocol, using the Bitcoin blockchain as a timestamp notary.
Additionally this package provides timestamping of PGP signed Git commits, and
verification of timestamps for both Git commits as a whole, and individual
files within a Git repository.


## Requirements and Installation

* Python3 >= 3.4.2
* python-bitcoinlib >= 0.6.1
* GitPython >= 2.0.8 (optional, required only for Git commit rehashing support)

Additionally while OpenTimestamps can *create* timestamps without a local
Bitcoin node, to *verify* timestamps you need a local Bitcoin Core node (a
pruned node is fine). You also need to set the `rpcuser` and `rpcpassword`
options in `~/.bitcoin/bitcoin.conf` to allow the OpenTimestamps client to
connect to your node via the RPC interface.

The two required libraries are available via PyPI, and can be installed with:

    pip3 install -r requirements.txt

Once those libraries are installed, you can run the utilities directory out of
the repository; there's no system-wide installation process yet.


## Usage

### Timestamping a File

    ./ots stamp <file>


### Verifying a Timestamp

    ./ots verify <file>.ots


### Timestamping and Verifying PGP Signed Git Commits

See `doc/git-integration.md`.


## Compatibility Expectations

OpenTimestamps is alpha software, so it's possible that timestamp formats may
have to change in the future in non-backward-compatible ways. However it will
almost certainly be possible to write conversion tools for any
non-backwards-compatible changes.

It's very likely that the REST protocol used to communicate with calendars will
change, including in backwards incompatible ways. In the event happens you'll
just need to upgrade your client; existing timestamps will be unaffected.


## Known Issues

* Need unit tests for the client.

* While it's (hopefully!) not possible for a mallicious timestamp to cause the
  verifier to use more than a few MB of RAM, or go into an infinite loop, it is
  currently possible to make the verifier crash with a stack overflow.

* Git tree re-hashing support fails on certain Unicode filenames; this appears
  to be due to bugs in the underlying GitPython library.

* Git annex support only works with the SHA256 and SHA256E backends.

* Errors in the Bitcoin RPC communication aren't handled in a user-friendly
  way.

* It's unclear if SSL certificates for remote calendars are checked correctly,
  probably not on most (all?) platforms.

* We don't do a good job sanity checking timestamps given to us by remote
  calendars. A malicious calendar could cause us to run out of RAM, as well as
  corrupt timestamps in (recoverable) ways (stack overflow comes to mind). Note
  the previous known issue!

* Due to the timestamp cache, a malicious calendar could also cause unrelated
  timestamps to fail validation. However it is _not_ possible for a malicious
  calendar to create a false-positive.
