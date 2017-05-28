# OpenTimestamps Client Release Notes

## v0.4.0-PENDING

Minor breaking change: `git-gpg-wrapper` now throws an error if
`--rehash-trees` is used when GitPython isn't installed.

* Remote Bitcoin nodes are now supported.
* New SHA1 collision example.
* Better error handling.
* `ots info` now shows the results of operations in verbose mode.


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
