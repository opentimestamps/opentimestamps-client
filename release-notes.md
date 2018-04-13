# OpenTimestamps Client Release Notes

## v0.6.0

* Git tree rehashing is now always enabled; the `--rehash-tree` option is now
  ignored. This means that timestamps can be extracted for individual files
  within Git repos timestamped with this version onwards using the
  `ots git-extract` subcommand.
* Fixed crash when trying to timestamp git commits with very large commit
  messages.
* Standard app directory locations are now used, in particular for the
  timestamp cache.

### New Calendar Server

Thanks to Vincent Cloutier from Catallaxy, who has committed to running it
indefinitely.

This means that Peter Todd is no longer a single-point of failure for OTS
clients with default settings. By default both the `ots` client and the git
commit timestamper only consider a timestamp complete if at least two calendars
replied; previously Peter ran two out of three calendars. With the new
Catallaxy calendar, that's two out of four, which means as long as the other
two calendars are operating clients will continue to function with default
settings even if all of Peter's calendars are down.


### Bitcoin Timestamp Display Precision

Previously we'd display Bitcoin timestamps with precision down to the second,
which misrepresents how precise a Bitcoin timestamp can actually be as
adversarial miners can get away with creating blocks whose timestamps are
inaccurate by multiple hours, or more. This has been changed to rounding off to
the nearest day, which better represents the actual accuracy of a Bitcoin
timestamp.

Examples of the new UX:

```
$ ots verify examples/empty.ots
Assuming target filename is 'examples/empty'
Success! Bitcoin block 129405 attests existence as of 2011-06-08 EDT
```

```
$ git tag -v opentimestamps-client-v0.5.1
object dcc45495b682c522170e8c2148b4759632e9d7fa
type commit
tag opentimestamps-client-v0.5.1
tagger Peter Todd <pete@petertodd.org> 1513029381 -0500

Release opentimestamps-client-v0.5.1
ots: Got 1 attestation(s) from https://finney.calendar.eternitywall.com
ots: Got 1 attestation(s) from https://bob.btc.calendar.opentimestamps.org
ots: Success! Bitcoin block 498825 attests existence as of 2017-12-11 EST
ots: Good timestamp
gpg: Signature made Mon 11 Dec 2017 04:56:22 PM EST
gpg:                using RSA key 2481403DA5F091FB
gpg: Good signature from "Peter Todd <pete@petertodd.org>"
gpg:                 aka "[jpeg image of size 5220]"
```

For those who do want a more precise timestamp, the height of the block
attesting to the timestamp is now displayed, allowing a manual investigation of
it.


## v0.5.1

Updated dependencies, which ultimately means the segwit-supporting
`python-bitcoinlib` v0.9.0 is used instead of the non-segwit v0.8.0


## v0.5.0

Installation via `setup.py` is now supported!

Breaking change: The remote calendar whitelist options have been reworked. The
new behavior is that the `--whitelist` option adds additional remote calendars
to the default whitelist. If you don't want to use the default whitelist, it
can be disabled with the `--no-default-whitelist` option, replacing the prior
`--no-remote-calendars` option, which no longer exists.


## v0.4.0

Minor breaking change: `git-gpg-wrapper` now throws an error if
`--rehash-trees` is used when GitPython isn't installed.

Note that the `pysha3` library is now a required dependency.

* Remote Bitcoin nodes are now supported.
* New SHA1 collision example.
* Better error handling.
* `ots info` now shows the results of operations in verbose mode.
* Support for decoding, but not verifying, Ethereum block header attestations.
* Support for the `keccak256` opcode (required for Ethereum-using proofs).


## v0.3.3

While the actual code changes are pretty minor, this release is an important
step forward for the OpenTimestamps project in terms of robustness.

First of all, we've added a new calendar: https://finney.calendar.eternitywall.com/

The new calendar is run by Eternity Wall, which means it's both separate
infrastructure, and separate administration, to the existing two calendars run
by Peter Todd. By default the OpenTimestamps client requires at least two
calendars to reply within five seconds for a timestamp to be created; if less
than two reply the stamp command returns an error (also true for the Git
support). If all three calendars reply within five seconds, all three
attestations are saved in the timestamp proof.

The upshot of this is availability: the default configuration can now tolerate
downtime on any one calendar with no problems. Secondly, all three calendars
would have to fail for a timestamp to fail to be committed to Bitcoin in a
timely manner.

Finally all three calendars now allow you to download a full copy of their
calendar data; with that data you can verify any timestamp ever created by
them. See the README for details on how this works.


## v0.3.2

* SOCKS5 proxy now supported, e.g. to route remote calendar requests through Tor.
* `ots upgrade` now works on Windows.
* `ots upgrade` now supports `--dry-run`
* n-of-m w/ timeouts now used when creating timestamps.


## v0.3.1

* Fixed crash when verifying non-timestamped Git commits.


## v0.3.0

(Minor) breaking change: `git-gpg-wrapper` has been renamed to
`ots-git-gpg-wrapper` to make the name unique to OpenTimestamps.

* Timestamps are now submitted to multiple calendars in parallel.
* `ots git-extract` now works with relative paths.
* Improved error message when `ots git-extract` used on a non-rehash-trees commit.
* `ots git-extract` no longer clobbers existing timestamp files.
* `ots info` output is now ordered consistently across multiple invocations.


## v0.2.3

Note that the the required version of python-bitcoinlib has been increased in
this release.

* Use dynamic path insert rather than symlink for compatibility with Windows.
* Fix an incompatibility with newer Git versions
* Improve GPG wrapper


## v0.2.2

* Display reason given from calendar when a timestamp commitment isn't found,
  e.g. because the timestamp is pending confirmation in the Bitcoin blockchain.
* Improved error messages.


## v0.2.1

* Improved error messages when ~/.bitcoin/bitcoin.conf can't be read.
* Improved error messages for IO errors.
* Support for attestations by unknown notaries (forward compatibility).
* Improved handling of corrupt timestamps: It should not be possible for
  a malicious remote calendar to do anything other than make us think a
  timestamp is invalid, a problem that's relatively easy to fix.
* Attestations from remote calendars are always displayed in the logs, even if
  they duplicate attestations from other calendars.


## v0.2.0

Major rewrite and public alpha release.


## v0.1.0

Initial version, not widely used.
