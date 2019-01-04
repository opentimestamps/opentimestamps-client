# OpenTimestamps Client

Command-line tool to create and validate timestamp proofs with the
OpenTimestamps protocol, using the Bitcoin blockchain as a timestamp notary.
Additionally this package provides timestamping of PGP signed Git commits, and
verification of timestamps for both Git commits as a whole, and individual
files within a Git repository.

## Requirements

* Python3

While OpenTimestamps can *create* timestamps without a local Bitcoin node, to
*verify* timestamps you need a local Bitcoin Core node (a pruned node is fine).


## Installation

Either via PyPi:

    $ pip3 install opentimestamps-client

or from source:

    $ python3 setup.py install

On Debian (Stretch) you can install the necessary system dependencies with:

    sudo apt-get install python3 python3-dev python3-pip python3-setuptools python3-wheel

## Usage

Creating a timestamp:

    $ ots stamp README.md
    Submitting to remote calendar https://a.pool.opentimestamps.org
    Submitting to remote calendar https://b.pool.opentimestamps.org
    Submitting to remote calendar https://a.pool.eternitywall.com

You'll see that `README.md.ots` has been created with the aid of three remote
calendars. We can't verify it immediately however:

    $ ots verify README.md.ots
    Assuming target filename is 'README.md'
    Calendar https://alice.btc.calendar.opentimestamps.org: Pending confirmation in Bitcoin blockchain
    Calendar https://bob.btc.calendar.opentimestamps.org: Pending confirmation in Bitcoin blockchain
    Calendar https://finney.calendar.eternitywall.com: Pending confirmation in Bitcoin blockchain

It takes a few hours for the timestamp to get confirmed by the Bitcoin
blockchain; we're not doing one transaction per timestamp.

However, the client does come with a number of example timestamps which you can
try verifying immediately. Here's a complete timestamp that can be verified
locally:

    $ ots verify examples/hello-world.txt.ots
    Assuming target filename is 'examples/hello-world.txt'
    Success! Bitcoin block 358391 attests existence as of 2015-05-28 CEST

You can specify JSON-RPC credentials (`USER` and `PASS`) for a local bitcoin node like so:

    $ ots --bitcoin-node http://USER:PASS@127.0.0.1:8332/ verify examples/hello-world.txt.ots
    Assuming target filename is 'examples/hello-world.txt'
    Success! Bitcoin block 358391 attests existence as of 2015-05-28 CEST

Incomplete timestamps are ones that require the assistance of a remote calendar
to verify; the calendar provides the path to the Bitcoin block header:

    $ ots verify examples/incomplete.txt.ots
    Assuming target filename is 'examples/incomplete.txt'
    Got 1 new attestation(s) from https://alice.btc.calendar.opentimestamps.org
    Success! Bitcoin block 428648 attests existence as of 2016-09-07 CEST

The client maintains a cache of timestamps it obtains from remote calendars, so
if you verify the same file again it'll use the cache:

    $ ots verify examples/incomplete.txt.ots
    Assuming target filename is 'examples/incomplete.txt'
    Got 1 attestation(s) from cache
    Success! Bitcoin block 428648 attests existence as of 2016-09-07 CEST

You can also upgrade an incomplete timestamp, which adds the path to the
Bitcoin blockchain to the timestamp itself:

    $ ots upgrade examples/incomplete.txt.ots
    Got 1 attestation(s) from cache
    Success! Timestamp is complete

Finally, you can get information on a timestamp, including the actual
commitment operations and attestations in it:

    $ ots info examples/two-calendars.txt.ots
    File sha256 hash: efaa174f68e59705757460f4f7d204bd2b535cfd194d9d945418732129404ddb
    Timestamp:
    append 839037eef449dec6dac322ca97347c45
    sha256
     -> append 6b4023b6edd3a0eeeb09e5d718723b9e
        sha256
        prepend 57d46515
        append eadd66b1688d5574
        verify PendingAttestation('https://alice.btc.calendar.opentimestamps.org')
     -> append a3ad701ef9f10535a84968b5a99d8580
        sha256
        prepend 57d46516
        append 647b90ea1b270a97
        verify PendingAttestation('https://bob.btc.calendar.opentimestamps.org')

### Timestamping and Verifying PGP Signed Git Commits

See `doc/git-integration.md`


## Privacy Security

Timestamping inherently records potentially revealing metadata: the current
time. If you create multiple timestamps in close succession it's quite likely
that an adversary will be able to link those timestamps as related simply on
the basis of when they were created; if you make use of the timestamp multiple
files in one command functionality (`./ots stamp <file1> <file2> ... <fileN>`)
most of the commitment operations in the timestamps themselves will be
identical, providing an adversary very strong evidence that the files were
timestamped by the same person. Finally, the REST API used to communicate with
remote calendars doesn't currently attempt to provide any privacy, although it
could be modified to do so in the future (e.g. with prefix filters).

File contents *are* protected with nonces: a remote calendar learns nothing
about the contents of anything you timestamp as it only ever receives an opaque
and meaningless digest. Equally, if multiple files are timestamped at once,
each file is protected by an individual nonce; the timestamp for one file
reveals nothing about the contents of another file timestamped at the same
time.

## Compatibility Expectations

OpenTimestamps is alpha software, so it's possible that timestamp formats may
have to change in the future in non-backward-compatible ways. However it will
almost certainly be possible to write conversion tools for any
non-backwards-compatible changes.

It's very likely that the REST protocol used to communicate with remote
calendars will change, including in backwards incompatible ways. If this
happens you'll just need to upgrade your client; existing timestamps will be
unaffected.

## Calendar Mirroring

As a short-term measure, the raw calendar data for the three calendar servers
in operation at this time can be downloaded directly. See
the `contrib/calendar-mirror.sh` script for details.

## Development

Use the setuptools development mode:

    python3 setup.py develop --user


## Known Issues

* Need unit tests for the client.

* Git tree re-hashing support fails on certain filenames with invalid unicode
  encodings; this appears to be due to bugs in the underlying GitPython
  library. As a work-around, you may find the `convmv` tool useful to find and
  rename these files.

* Git annex support only works with the SHA256 and SHA256E backends.

* Errors in the Bitcoin RPC communication aren't handled in a user-friendly
  way.

* Not all Python platforms check SSL certificates correctly. This means that on
  some platforms, it would be possible for a MITM attacker to intercept HTTPS
  connections to remote calendars. That said, it shouldn't be possible for such
  an attacker to do anything worse than give us a timestamp that fails
  validation, an easily fixed problem.

* ots-git-gpg-wrapper doesn't yet check for you if the timestamp on the git commit
  makes sense.

* `bitcoin` package can cause issues, with ots confusing it with the
  required `python-bitcoinlib` package. A symptom of this issue is the
  message `AttributeError: module 'bitcoin' has no attribute
  'SelectParams'` or `JSONDecodeError("Expecting value", s, err.value) from None`. To remedy this issue, one must do the following:

```bash
# uninstall the packages through pip
pip3 uninstall bitcoin python-bitcoinlib

# remove the bitcoin directory manually from your dist-packages folder
rm -rf /usr/local/lib/python3.5/dist-packages/bitcoin

# reinstall the required package
pip3 install python-bitcoinlib
```
