OpenTimestamps Git Integration
==============================

While Git supports PGP signing for tags and commits natively, like other uses
of PGP a major caveat exists: How do you verify a signature from a revoked or
expired key? Joanna Rutkowska, co-founder of QubesOS, explains the problem on
her blog:

> My signing keys (e.g. blog or Qubes code signing keys) do not have expiration
> dates. This is not laziness. There is a fundamental problem with using an
> expiration date on keys used for code signing (e.g. git tag -s), because it
> is unclear what the outcome should be when one verifies some old code
> (written and signed when the key was still valid) in the future when the key
> has already expired?
>
> Naturally we would like the old code, written and signed when the key was
> still valid, to continue to verify fine also in the future, after the key
> expires (and the developer passed away, perhaps). However, it is very
> problematic to prevent the attacker from creating falsified code pretending
> to be an old one.

-http://blog.invisiblethings.org/keys/

OpenTimestamps Git integration helps mitigate this problem by providing proof
that code-signing signatures existed prior to when a key expired or was
revoked.


How It Works
------------

Under the hood a Git commit is simply a few lines of text:

    $ git cat-file -p 7b94d37a71a236227c443e0f46e885101401020c
    tree 8faa3b9a240f4742d41b12fb62e95f8af25feb5e
    author Peter Todd <pete@petertodd.org> 1349397737 -0700
    committer Peter Todd <pete@petertodd.org> 1349397737 -0700
    
    Initial commit

A signed Git commit adds a ASCII-armored PGP signature:

    $ git cat-file -p a9d1ffc2e10dafcf17d31593a362b15c0a636bfc
    tree 548b1c88f537cd9939edeea094bfaff094f20874
    parent 53c68bc976c581636b84c82fe814fab178adf8a6
    author Peter Todd <pete@petertodd.org> 1432826886 -0400
    committer Peter Todd <pete@petertodd.org> 1432827857 -0400
    gpgsig -----BEGIN PGP SIGNATURE-----
     
     iQGrBAABCACVBQJVZzfSXhSAAAAAABUAQGJsb2NraGFzaEBiaXRjb2luLm9yZzAw
     MDAwMDAwMDAwMDAwMDAwMjFmZmUwZDk5ZmY5ZTJmNjI4YTc2M2JmN2NkZDUzYjY4
     YzEzYzYxNzg5ZTdhNDMvFIAAAAAAFQARcGthLWFkZHJlc3NAZ251cGcub3JncGV0
     ZUBwZXRlcnRvZC5vcmcACgkQJIFAPaXwkfuCcgf9HXnqAF17nzlv6slq4qdX2agQ
     7rPWUtD8tGt0KVYAPmmijZ3guDRF4ISuUgcer4ixmBBezssKQG3ghqnlhq6OudBW
     T/MpVhkhIG3EDs58muhCsORPqO0CirhDiA5QFcZdCj/R7PDbZEygmI5OpS0HJK1j
     9oeDEDuItV/450tfjd4eSOcnSkqvQBO822U70VdmO4MbHkG5kZ1mHJ6FyxfW737b
     hgayzXP1rEURmobsczBXa8jUyg/c30vxwV9yJkzWNFISvZK4/nXgnyWk5ft8cn5V
     YzMjt5lQuJwX/r6/MdRPRorPIOxdxUQzSN+8s8soZ3gqdIH/fuqCra7s2cntrw==
     =Lfsu
     -----END PGP SIGNATURE-----
    
    Add working ots command line utility

What the signature actually signs is simply the commit minus the signature
itself; in the above example the exact data the signature signs is:

    $ git cat-file -p a9d1ffc2e10dafcf17d31593a362b15c0a636bfc
    tree 548b1c88f537cd9939edeea094bfaff094f20874
    parent 53c68bc976c581636b84c82fe814fab178adf8a6
    author Peter Todd <pete@petertodd.org> 1432826886 -0400
    committer Peter Todd <pete@petertodd.org> 1432827857 -0400
    
    Add working ots command line utility

You can verify this yourself manually with a bit of cut-and-pasting.
Interestingly, if you ask GnuPG to verify a ASCII-armored signature with
additional stuff at the end that it doesn't recognise, the verification still
works. This allows us to append our timestamp to the end of the signature,
while still maintaining compatibility with non-OpenTimestamps-aware Git
clients:

    $ git cat-file -p 48034652a83bb2119777bac5d84d24552454ab1f
    tree 25ebb56d6818abc82c8ff7ce9ac801b7ef052094
    parent d265224445754a997d0bf06662567ed8c0d4dc25
    author Peter Todd <pete@petertodd.org> 1473060568 -0400
    committer Peter Todd <pete@petertodd.org> 1473060568 -0400
    gpgsig -----BEGIN PGP SIGNATURE-----
     
     iQEcBAABCAAGBQJXzR7wAAoJEGOZARBE6K+yMT4H/jEhfBqe3Nr93SHdwVJ14rGg
     WIOtBG4t9KmJjYCBTXgQRTTI/0F+gGulMRr5jeDTgmQpPNKIHKjv62kPPtcxqQQr
     3AfByOjNLja3saAxEwFI++gkNgdeD7eqJex6P0OnVVixklyznVXvtEq1UoESBHRp
     MIGbLpR3jAgxT58ZPrezHu9p2ifT/uT6MrwjYlvJzOfjK2t9sBLXfUUtzWfmxUNA
     +wfQv/X5vePzcZth0AIKWwPAm77HtBGlJXYg9e8GPUBS6t6t2nHkyQIsgXYeFwFy
     9nf4W3yi1hbuvEV2DtqGQZjF/s9GIhLBS5I5p0RGy4zt55inGImlSekPBSuKzmo=
     =7pUu
     -----END PGP SIGNATURE-----
     -----BEGIN OPENTIMESTAMPS GIT TIMESTAMP-----
     
     AQDwEPyUcFjpQf0P0ntzUeqBn8MI8QRXzR7zAIPf4w0u+QyOLi1odHRwczovL2Fs
     aWNlLmJ0Yy5jYWxlbmRhci5vcGVudGltZXN0YW1wcy5vcmc=
     -----END OPENTIMESTAMPS GIT TIMESTAMP-----
    
    Add Git GnuPG wrapper
    
    Allows signed git commits to be timestamped.


Usage
-----

To create and verify these signatures we simply wrap the gpg binary with our
own code, `ots-git-gpg-wrapper`. Git allows you to override the default GnuPG
binary (`/usr/bin/gpg`) with your own using the `gpg.program` config option.
Unfortunately that option doesn't let you set additional command line flags, so
we use one more wrapper, `ots-git-gpg-wrapper.sh`. You can set all this up with the
following:

    git config --global gpg.program <path to ots-git-gpg-wrapper.sh>

Now try creating a test repository and signing a commit:

    $ git init
    Initialized empty Git repository in /tmp/test/.git/
    $ echo "Hello World!" > greeting
    $ git add greeting
    $ git commit -S -m 'initial commit'
    ots: Submitting to remote calendar 'https://pool.opentimestamps.org'
    [master (root-commit) 6ccf07f] initial commit
     1 file changed, 1 insertion(+)
     create mode 100644 greeting

You can use `git cat-file` to see the new commit:

    $ git cat-file -p HEAD
    tree 7b83077600c4fc88b2e519d4bc0a0dea6d3d6396
    author Peter Todd <pete@petertodd.org> 1473132873 -0400
    committer Peter Todd <pete@petertodd.org> 1473132873 -0400
    gpgsig -----BEGIN PGP SIGNATURE-----
     
     iQEbBAABCAAGBQJXzjlLAAoJEGOZARBE6K+yEt8H+JF4cUkfurgKqVEiRFsQXirZ
     iO6v79SjdRVTXoHIikDoEnLaScr1BpHVxBqNakGJoRaPnOJYZEMNm2ICmnDJbSAQ
     llNUc3sUWfrnIcbo6wm5PVAUMDKKJFgHFK0dLnmwbDNlOY/1qvikSkGq1n/fHVDm
     iRQweH+p47StJt/255TsknuSMu+gllGByHcAcLRPFkcwgvHp/P6MZ26yxGmRu3u4
     Kmo7iEMlTSwJZTqjmAWH0uxm2wVaKRcxaJx1sUAkuOvCdXxDTVZdxiRupdBdicLQ
     UsU4ZKoEKte7Hhe10d4c0LmIHGgrPc3jH+DL3zD5r1n6BLHzDuTFbnXTWZnpAg==
     =/mbV
     -----END PGP SIGNATURE-----
     -----BEGIN OPENTIMESTAMPS GIT TIMESTAMP-----
     
     AQDwEJbLmWPCiB5L5H3tY8DJywAI8QRXzjlO8AiALKz7iooxNwCD3+MNLvkMji4t
     aHR0cHM6Ly9hbGljZS5idGMuY2FsZW5kYXIub3BlbnRpbWVzdGFtcHMub3Jn
     -----END OPENTIMESTAMPS GIT TIMESTAMP-----
    
    initial commit

As usual you can verify both the signature and timestamp with `git log`. It
does takes some time for the calendar server to aggregate your timestamp with
other timestamps and commit them in the Bitcoin blockchain, so if you do this
right away OpenTimestamps will tell you that the timestamp can't be verified:

    $ git log --show-signature
    commit 6ccf07f8dc003728d5366eb435b883057306f1d1
    ots: Calendar b'https://alice.btc.calendar.opentimestamps.org': No timestamp found
    ots: Pending attestation b'https://alice.btc.calendar.opentimestamps.org'
    ots: Could not verify timestamp
    gpg: Signature made Mon 05 Sep 2016 08:34:35 PM PDT
    gpg:                using RSA key 6399011044E8AFB2
    gpg: Good signature from "Peter Todd <pete@petertodd.org>" [ultimate]
    gpg:                 aka "[jpeg image of size 5220]" [ultimate]
    Author: Peter Todd <pete@petertodd.org>
    Date:   Mon Sep 5 23:34:33 2016 -0400
    
        initial commit

However, if we wait a few hours the timestamp will be completed and can
verified:

    $ git log --show-signature
    commit 6ccf07f8dc003728d5366eb435b883057306f1d1
    ots: Got 1 new attestation(s) from b'https://alice.btc.calendar.opentimestamps.org'
    ots: Success! Bitcoin attests data existed as of Fri Sep  9 23:03:52 2016 UTC
    ots: Good timestamp
    gpg: Signature made Mon 05 Sep 2016 08:34:35 PM PDT
    gpg:                using RSA key 6399011044E8AFB2
    gpg: Good signature from "Peter Todd <pete@petertodd.org>" [ultimate]
    gpg:                 aka "[jpeg image of size 5220]" [ultimate]
    Author: Peter Todd <pete@petertodd.org>
    Date:   Mon Sep 5 23:34:33 2016 -0400
    
        initial commit

Additionally, since OpenTimestamps maintains a cache of known timestamps, after
you successfully retrieve a timestamp once you never need to rely on the remote
calendar server again:

    $ git log --show-signature
    commit 6ccf07f8dc003728d5366eb435b883057306f1d1
    ots: Got 1 attestation(s) from cache
    ots: Success! Bitcoin attests data existed as of Fri Sep  9 23:03:52 2016 UTC
    ots: Good timestamp
    gpg: Signature made Mon 05 Sep 2016 08:34:35 PM PDT
    gpg:                using RSA key 6399011044E8AFB2
    gpg: Good signature from "Peter Todd <pete@petertodd.org>" [ultimate]
    gpg:                 aka "[jpeg image of size 5220]" [ultimate]
    Author: Peter Todd <pete@petertodd.org>
    Date:   Mon Sep 5 23:34:33 2016 -0400
    
        initial commit


Signing and Timestamping Tags
-----------------------------

Under the hood, tags work much the same way as commits. Let's create one:

    $ git tag -s -m 'Hello World!' initial-commit HEAD
    ots: Submitting to remote calendar 'https://pool.opentimestamps.org'

Similar to a commit, a signed tag is just a normal tag with a PGP signature; a
timestamped tag is a normal signed tag with a timestamp:

    $ git cat-file -p initial-commit
    object 6ccf07f8dc003728d5366eb435b883057306f1d1
    type commit
    tag initial-commit
    tagger Peter Todd <pete@petertodd.org> 1473148175 -0400
    
    Hello World!
    -----BEGIN PGP SIGNATURE-----
    
    iQEcBAABCAAGBQJXznUQAAoJEGOZARBE6K+y5OQH/jJ18Eo9owPnMdTrkiS2lSaE
    /zToaC6LLqCfgxUPh4kpEKcH/sO9oBE6idayXs8/eb+twUu/52pDAWGcnquJr2bh
    oORzsnk6arCuCrYTa/0JcBK5Ff34HyaXH78qT26ts4cQKWJwRaHUbuFeXfBlfHHe
    f/0rleGNl9LOzDLWFOY9KHLDX3O7d71MXzMaOGCwjGYaVzyT7DOVfGumvkGvXmEO
    Fu/wKhUYTjqqiJHHsfmvpPR+pVGOCZgMA9Cc/9zX5OB6bDcBWHzGGNIouzBStrJ+
    4pO+J2JzgNKIV3EBl99o1Qca5IqrCRYiaAHwl4cBlDt+I8KqbYO4x5RKrlCEpPg=
    =PY8g
    -----END PGP SIGNATURE-----
    -----BEGIN OPENTIMESTAMPS GIT TIMESTAMP-----
    
    AQDwEP7aFKxEJU3S/IqqGbdrOccI8QRXznUU8AgjirrYajh9VQCD3+MNLvkMji4t
    aHR0cHM6Ly9hbGljZS5idGMuY2FsZW5kYXIub3BlbnRpbWVzdGFtcHMub3Jn
    -----END OPENTIMESTAMPS GIT TIMESTAMP-----

Just like commits, you can verify them as you would any other tag:

    $ git tag -v initial-commit
    object 6ccf07f8dc003728d5366eb435b883057306f1d1
    type commit
    tag initial-commit
    tagger Peter Todd <pete@petertodd.org> 1473148175 -0400
    
    Hello World!
    ots: Got 1 new attestation(s) from b'https://alice.btc.calendar.opentimestamps.org'
    ots: Success! Bitcoin attests data existed as of Tue Sep  6 01:20:11 2016 UTC
    ots: Good timestamp
    gpg: Signature made Tue 06 Sep 2016 12:49:36 AM PDT
    gpg:                using RSA key 6399011044E8AFB2
    gpg: Good signature from "Peter Todd <pete@petertodd.org>"
    gpg:                 aka "[jpeg image of size 5220]"

However, unlike commits you probably make tags relatively infrequently, and
they're used for more important things like software releases. Every timestamp
we've created above depended on a remote calendar server. While you're not
trusting the calendar server for the accuracy of the timestamp - that's done
by the Bitcoin blockchain - you are trusting that server not to lose data: if
the calendar server loses the commitment your timestamp used, you won't be able
to verify that the timestamp was valid.

As an additional measure of safety, OpenTimestamps can also create standalone
timestamps that don't depend on a calendar server at all with the `--wait`
option. With `--wait` OpenTimestamps still uses a calendar server, but once the
initial timestamp has been created it waits until the timestamp has been
completed by the Bitcoin blockchain, and saves the completed timestamp. This
may take up to a few hours, but in the case of an important software release
that may not be a big deal. To use this you (currently) have to manually add
`--wait` to the `ots-git-gpg-wrapper.sh` script. Then sign the tag as usual:

    $ git tag -s -m 'Completed timestamp' full-timestamp HEAD
    ots: Submitting to remote calendar 'https://pool.opentimestamps.org'
    ots: Calendar b'https://alice.btc.calendar.opentimestamps.org': No timestamp found
    ots: Timestamp not complete; waiting 30 sec before trying again
    
    <snip>
    
    ots: Calendar b'https://alice.btc.calendar.opentimestamps.org': No timestamp found
    ots: Timestamp not complete; waiting 30 sec before trying again
    ots: Got 1 new attestation(s) from 'https://pool.opentimestamps.org'

If we inspect the contents of the tag, we see that the timestamp is quite a bit
larger. That extra data is the transaction used to create the timestamp, and a
merkle path to the block header's merkleroot:

    $ git cat-file -p full-timestamp
    object 6ccf07f8dc003728d5366eb435b883057306f1d1
    type commit
    tag full-timestamp
    tagger Peter Todd <pete@petertodd.org> 1473148584 -0400
    
    Completed timestamp
    -----BEGIN PGP SIGNATURE-----
    
    iQEcBAABCAAGBQJXznaoAAoJEGOZARBE6K+yfHUH/1Z+Z80X5dUXu2MkuJA2zwBn
    YNehHVDdaiTtUotNYwt5eZF6F/PnV/UFVIz+ui/nECk6450j3guuVsDGwGV7Qk0I
    rbBtWstE3bSEe6yb8xMnzbtXeEL0NxNXvJg7IGhyIyXW/D5mEBy86IkfTmC1uSne
    qpJA8SJSqiXqjAIGOMcoDBaGTrhO48fVBqtsM8UITW6FkkIzFSwWztvfBwO3BC69
    m16hKATkF9zjdnRrWZhU7lWUc2ZIBUiQR+a5zu4cr9APREb57rKDRxME9pN72QSA
    f4OOVrEI17KwDJL8k4xtgZbsgML7qwYE4l6c1UgcvOZaT24+Na1gCfuVc1VRJ80=
    =dPv/
    -----END PGP SIGNATURE-----
    -----BEGIN OPENTIMESTAMPS GIT TIMESTAMP-----
    
    AQDwEJHZKrfswQ5TNCCt59Kg++8I8QRXznas8AjyXlO5ULkRE/8Ag9/jDS75DI4u
    LWh0dHBzOi8vYWxpY2UuYnRjLmNhbGVuZGFyLm9wZW50aW1lc3RhbXBzLm9yZwjw
    IC55AvT++3VPH6R3XkvSlYxAAzdslE0fGiWwMc7vzX60CPEgtMdWl8Kk4bzaVWTl
    apNcnVB2rV7zCW9L8iOL/f5gJfQI8SChTzPMBPSM8asTQiVUSi6oep4WOJW47W6Q
    o+bwzv5fdAjwILly27BIebVJdIIVVZcFIINIsoPKrihrdGt9o8uF17VHCPGvAQEA
    AAABUjjgsnadsq1b1CYD/H0jawI62wpx6K3VAbYB3tJnscEAAAAASUgwRQIhAPzI
    MoDCDedE4g1+gRJtxYNqAn+daewcujB8/gYH25mHAiBRsL6O5y6awkYDeYby6oX+
    cCkfPnWQzqZGpuqz/AmlswH9////Ag/NQgAAAAAAIyECcHVURStvbTk11K7+dQhY
    PCb7BmBY63ESILyWppNWFa2sAAAAAAAAAAAiaiDwBOKJBgAICPAgEFsL/WbJjUEN
    Ux/JleuBvXezXGFTpfCLudP0DqearhQICPEgiQHZlhpvrWgwNOG0PRppbKUemMyr
    fdOTK6pyEHwLyrUICPAgl8sEvk94yqCnS1ttEALyKQHHAZIlh11qI9XUL39L5AAI
    CPAgqsnWHZViE1QQS2BehnbAMU2c1BrWWOhLIZ5Y4cyuqdkICPEg/oA0mZLSWzdg
    T4NfF4KbMRSVtLLg7ohGwOB7xqeEN9UICPEguZtk0Etw0WsvNBwd3QoFkpOefrPm
    sR7BYQKqIgZMh78ICPAgmi96daOSE/YhUmo94xk+8XDvipN21n/lsAGmteoSy0UI
    CPEgdSWz6QlENV0J8eF0LQ7ubSXdIuaLesBoZSY/hJnJw1wICPAgxwWV7Ob92QGf
    rgJw0xx+S4fWXi48M8R7pvpLXdRAzSQICPEg3tL13Um/N1CaP/Emnt63GNOIEhB7
    EowkE3wtqOosGs8ICPEgwhAv1F4O8LV/QqjiWLXqTX9/plyXlTYu12bWj3IZ774I
    CAAFiJYNc9cZAQPjkxo=
    -----END OPENTIMESTAMPS GIT TIMESTAMP-----

Finally, if verify this timestamp, we see that OpenTimestamps verifies the
timestamp directly against the Bitcoin blockchain, without contacting any
calendar servers:

    $ git tag -v full-timestamp
    object 6ccf07f8dc003728d5366eb435b883057306f1d1
    type commit
    tag full-timestamp
    tagger Peter Todd <pete@petertodd.org> 1473148584 -0400
    
    Completed timestamp
    ots: Success! Bitcoin attests data existed as of Tue Sep  6 01:20:11 2016 UTC
    ots: Good timestamp
    gpg: Signature made Tue 06 Sep 2016 12:56:24 AM PDT
    gpg:                using RSA key 6399011044E8AFB2
    gpg: Good signature from "Peter Todd <pete@petertodd.org>"
    gpg:                 aka "[jpeg image of size 5220]"
