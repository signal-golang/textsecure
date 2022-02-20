# TextSecure library and command line test client for Go

This is a Go package implementing the TextSecure **push data** (i.e. not encrypted SMS) protocol v3 including the Axolotl ratchet.

The included sample command line app can send and receive text messages and attachments and supports group chat.

**The API presented by the package is in flux**,  mainly driven by the needs of https://github.com/nanu-c/axolotl

Automatically generated documentation can be found on [GoDoc](https://pkg.go.dev/github.com/signal-golang/textsecure)

Installation
------------

This command will install both the library and the test client.

    go get github.com/signal-golang/textsecure/cmd/textsecure

textsecure also depends on [crayfish](https://github.com/nanu-c/crayfish) which is a Go library for interacting with the upstream [libsignal-client](https://github.com/signalapp/libsignal-client) library. It's currently used for registration and decryption of messages. libzkgroup is used for the groupv2 protocol and is add by [this go wrapper] (https://github.com/nanu-c/zkgroup). It has to be added to the `LD_LIBRARY_PATH` environment variable. Crayfish is built with `cago build` and has to be placed next to the `textsecure` binary.

Configuration
-------------

Copy cmd/textsecure/.config to a directory and modify it, then run the tool from that directory.
It will create .storage to hold all the protocol state. Removing that dir and running the tool again will trigger a reregistration with the server.

Usage
-----

**Do not run multiple instances of the app from the same directory, it (and the server) can get confused**

This will show the supported command line flags

    textsecure -h

Running the command without arguments will put it in receiving mode, and once it receives a message it will be able to talk to that contact.

Discussions
-----------

User and developer discussions happen on the [mailing list](https://groups.google.com/forum/#!forum/textsecure-go)
