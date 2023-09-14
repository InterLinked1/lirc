# LIRC
IRC client and client library for C

This is a lightweight IRC (Internet Relay Chat) client library written in C. It is released under the Lesser General Public License, so you can easily link to it from your own software.

Additionally, if you run `make client`, it will compile a fully-functional terminal-based IRC client that uses the library. This was written primarily for testing the library, but it can be used as a client more or less like any other. It is fast and designed not to abstract away too much of the underlying IRC protocol. The major limitation is the client only supports connecting to one server at a time (which may or may not matter to you).

## Building library

LIRC is linked with and depends on OpenSSL for its TLS support. Otherwise, it has no other linking dependencies.

Run `make library` to build the library and then run `make install` to install the library on your system.

You can then link to the library using `-lirc`.

The header file to include is `#include <lirc/irc.h>`.

## Building LIRC client

Build the library, and then run `make client`. The `irc` binary produced is the client program.

You may use this client both as a functional IRC client and as a reference for library usage.
