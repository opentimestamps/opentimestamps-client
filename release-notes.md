# OpenTimestamps Client Release Notes

## v0.3.2-PENDING

* SOCKS5 proxy now supported, e.g. to route remote calendar requests through Tor.


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
