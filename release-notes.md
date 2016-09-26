# OpenTimestamps Client Release Notes

## v0.2.1-PENDING

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
