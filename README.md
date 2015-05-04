scanssh - Fast SSH server and open proxy scanner
================================================

ScanSSH scans the given addresses and networks for running services.
It mainly detects open proxies and Internet services.  For known
services, ScanSSH will query their version number and displays the
results in a list.

This program was originally written under OpenBSD as a personal
measurement tool.  However, besides gathering statistics, it's also
useful for other purposes such as ensuring that all machines on your
network run the latest SSH versions, etc...

It is BSD-licensed, please see the source files.

The program requires

        libpcap - http://www.tcpdump.org/
        libevent - http://www.monkey.org/~provos/libevent/
        libdnet - http://libdnet.sourceforge.net/

Built and tested on NetBSD, OpenBSD and Linux, but it should also run with
other UNIX-like operating systems.

To build,

        ./configure
        make
        make install

should make you happy.

ACKNOWLEDGEMENTS
================

Thanks to Marius Eriksen for release testing.

Thanks to the original author Niels Provos <provos@citi.umich.edu>
http://www.citi.umich.edu/u/provos

MAINTAINER
==========

Since Niels doesn't have any time to take care about this piece of software
and I'm one of the Fedora packagers for it, I took it over and do maintain it
now on https://github.com/ofalk/scanssh.


[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/ofalk/scanssh/trend.png)](https://bitdeli.com/free "Bitdeli Badge")

