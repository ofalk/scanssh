AUTOMAKE_OPTIONS = foreign no-dependencies

bin_PROGRAMS = scanssh

scanssh_SOURCES = scanssh.c atomicio.c exclude.c connecter.c xmalloc.c \
	interface.c socks.c http.c telnet.c exclude.h interface.h \
	scanssh.h socks.h xmalloc.h
scanssh_LDADD = @LIBOBJS@ @PCAPLIB@ @EVENTLIB@ @DNETLIB@
CFLAGS = -O2 -Wall -g

INCLUDES = -I$(top_srcdir)/@DNETCOMPAT@ -I$(top_srcdir)/compat \
	@EVENTINC@ @PCAPINC@ @DNETINC@

man_MANS = scanssh.1

EXTRA_DIST = $(man_MANS) README acconfig.h \
	   md5.c err.c \
	   compat/libdnet/dnet.h \
	   compat/err.h compat/md5.h \
	   compat/sys/queue.h compat/sys/tree.h

DISTCLEANFILES = *~
