# python-opentimestamps

Python3 library for working with the OpenTimestamps protocol.



## Requirements

* Python3 3.4.2
* python-bitcoinlib v0.7.0
* GitPython 2.0.8 (optional: required only by `opentimestamps.core.git`)

Note that the version numbers represent what this library has been tested with;
newer versions will probably work as well.


## Installation

This library is still in heavy development, and doesn't have an official
version number yet; the OpenTimestamps client and server both use it as a Git
subtree, and it's suggested that you do the same if you want to use it in your
own projects for the time being.


## Structure

Similar to the author's `python-bitcoinlib`, the codebase is split between the
consensus-critical `opentimestamps.core.*` modules, and the
non-consensus-critical `opentimestamps.*` modules. The distinction between the
two is whether or not changes to that code are likely to lead to permanent
incompatibilities between versions that could lead to timestamp validation
returning inconsistent results between versions.


## Example Code

None yet; take a look at the unit tests under `opentimestamps/tests`, as well
as the OpenTimestamps Client and OpenTimestamps Server repositories:

https://github.com/opentimestamps/opentimestamps-client

https://github.com/opentimestamps/opentimestamps-server


## Unit tests

python3 -m unittest discover -v

Also, Travis support has been added.
