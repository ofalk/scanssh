FROM docker.io/centos

MAINTAINER Oliver Falk <oliver@linux-kernel.at>

RUN ln -sf /dev/stdout /var/log/messages
RUN yum -y install git gcc make libpcap-devel libdnet-devel libevent-devel automake; yum clean all
RUN pushd /var/tmp && git clone https://github.com/ofalk/scanssh.git && pushd scanssh && aclocal && automake && ./configure && make && make install
