FROM quay.io/centos/centos:stream9

MAINTAINER Oliver Falk <oliver@linux-kernel.at>

RUN ln -sf /dev/stdout /var/log/messages
RUN dnf -y install epel-release epel-next-release && dnf -y install git-core gcc make libpcap-devel libdnet-devel libevent-devel automake; yum clean all
RUN pushd /var/tmp && git clone https://github.com/ofalk/scanssh.git && pushd scanssh && aclocal && automake && ./configure && make && make install
