# LIRC
IRC client and client library for C

This is a lightweight IRC (Internet Relay Chat) library written in C. It is released under the Mozilla Public License, so you can easily use it in your own software.

Additionally, if you build this project, it will compile a fully-functional terminal-based IRC client that uses the library. This was written primarily for testing the library, but it can be used as a client more or less like any other. The major limitation is the client only supports connecting to one server at a time. (Personally, all the IRC channels I use are on `irc.libera.chat` these days, so this may or may not be a meaningful limitation for you.)

## Building LIRC client

To use LIRC (library only) in your program, you simply need `irc.c` and `irc.h`.

If you want to build the LIRC client, you need all the files. Simply clone the repo and run `make`. The `irc` binary produced is the client program.

LIRC is linked with and depends on OpenSSL for its TLS support. Otherwise, it has no other linking dependencies.
