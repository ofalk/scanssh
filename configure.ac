dnl Process this file with autoconf to produce a configure script.
AC_INIT([scanssh],[2.1.3.1],[https://github.com/ofalk/scanssh/issues])
AC_CONFIG_SRCDIR([scanssh])
AC_CONFIG_SRCDIR(scanssh.c)

AM_INIT_AUTOMAKE

dnl Check for system type.
dnl XXX - we do this to qualify our later feature checks, since some
dnl systems claim to support multiple features, but are quite b0rked.
AC_CANONICAL_HOST

dnl Initialize prefix.
if test "$prefix" = "NONE"; then
   prefix="/usr/local"
fi

dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

dnl XXX - Solaris sux.
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(nsl, gethostbyname)

dnl XXX - we need WinPcap developer's pack under Cygwin for win32

AC_DEFUN([SCANSSH_CYGWIN],
[
AC_REQUIRE([AC_CANONICAL_HOST])[]dnl
case $host_os in
    *cygwin* )
	if test -d /usr/include/mingw ; then
		CPPFLAGS="$CPPFLAGS -mno-cygwin"
		CFLAGS="$CFLAGS -mno-cygwin"
		AC_DEFINE(WIN32_LEAN_AND_MEAN, 1, 
		    [Define for faster code generation.])
		AC_CHECK_LIB(ws2_32, main)
		AC_CHECK_LIB(iphlpapi, main)
		AC_DEFINE(snprintf, _snprintf, 
		    [Use MingW32's internal snprintf])
	else
		AC_MSG_ERROR([need MingW32 package to build under Cygwin])
	fi
	AC_MSG_CHECKING(for WinPcap developer's pack)
	AC_ARG_WITH(wpdpack,
	[  --with-wpdpack=DIR      use WinPcap developer's pack in DIR],
	[ AC_MSG_RESULT($withval)
	  if test -f $withval/include/packet32.h -a -f $withval/lib/packet.a; then
	     owd=`pwd`
	     if cd $withval; then withval=`pwd`; cd $owd; fi
	     CFLAGS="$CFLAGS -I$withval/include"
	     LIBS="$LIBS -L$withval/lib -lpacket"
	  else
	     AC_MSG_ERROR(packet32.h or packet.a not found in $withval)
	  fi ],
	[ for dir in ${prefix} ${HOME}/WPdpack ; do
	     if test -f ${dir}/include/packet32.h -a -f ${dir}/lib/packet.a; then
	        CFLAGS="$CFLAGS -I${dir}/include"
		LIBS="$LIBS -L${dir}/lib -lpacket"
		have_pcap=yes
		break;
	     fi
	  done
	  if test "$have_pcap" != yes; then
	     AC_MSG_ERROR(WinPcap developer's pack not found)
	  fi
	  AC_MSG_RESULT(yes) ])
  * ) AC_MSG_RESULT(no)
  ;;
esac
])

dnl Checks for libraries.
AC_REPLACE_FUNCS(inet_aton inet_pton strsep getaddrinfo getnameinfo strlcpy strlcat arc4random)
needmd5=no
AC_CHECK_FUNCS(MD5Update, , [needmd5=yes])
if test $needmd5 = yes; then
   AC_LIBOBJ(md5)
fi
neederr=no
AC_CHECK_FUNCS(warnx, , [neederr=yes])
if test $neederr = yes; then
   AC_LIBOBJ(err)
fi

dnl Checks for libpcap
AC_MSG_CHECKING(for libpcap)
AC_ARG_WITH(libpcap,
[  --with-libpcap=DIR      use libpcap build directory],
[ case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     AC_MSG_RESULT($withval)
     if test -f $withval/pcap.h -a -f $withval/libpcap.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
	PCAPINC="-I$withval -I$withval/bpf"
	PCAPLIB="-L$withval -lpcap"
     else
        AC_MSG_ERROR(pcap.h or libpcap.a not found in $withval)
     fi
     ;;
  esac ],
[ if test -f ${prefix}/include/pcap.h; then
     PCAPINC="-I${prefix}/include"
     PCAPLIB="-L${prefix}/lib -lpcap"
  elif test -f /usr/include/pcap/pcap.h; then
     PCAPINC="-I/usr/include/pcap"
     PCAPLIB="-lpcap"
  elif test -f /usr/include/pcap.h; then
     PCAPLIB="-lpcap"
  else
     AC_MSG_RESULT(no)
     AC_MSG_ERROR(libpcap not found)
  fi
  AC_MSG_RESULT(yes) ]
)
AC_SUBST(PCAPINC)
AC_SUBST(PCAPLIB)

dnl Checks for (installed) libdnet
AC_ARG_WITH(libdnet,
[  --with-libdnet=DIR      use libdnet in DIR],
[ case "$withval" in
  yes|no)
     AC_MSG_ERROR(Please specify directory containing dnet-config when using --with-libdnet)
     ;;
  *)
     AC_MSG_CHECKING(for libdnet)
     AC_MSG_RESULT($withval)
     if test -f $withval/src/libdnet.a; then
	DNETINC="-I$withval/include"
	DNETLIB="-L$withval/src -ldnet `$withval/dnet-config --libs`"
     elif test -x $withval/bin/dnet-config; then
	DNETINC="`$withval/bin/dnet-config --cflags`"
	DNETLIB="`$withval/bin/dnet-config --libs`"
     else
        AC_MSG_RESULT(no)
        AC_MSG_ERROR(dnet-config not found in $withval/bin)
     fi
     ;;
  esac
  AC_MSG_RESULT(yes) ],
[ dnl This is the default case so let's just use AC_PATH_PROG! --CPK.
  AC_PATH_PROG(dnetconfig, dnet-config, "no")
  if test "$dnetconfig" = "no"; then
     AC_MSG_ERROR(dnet-config not found)
  else
     DNETINC="`$dnetconfig --cflags`"
     DNETLIB="`$dnetconfig --libs`"
  fi]
)

dnl We still need to check whether it's dnet or dumbnet as
dnl for example on Debian. We test by looking at the content
dnl of DNETLIB and derive from the library name what version
dnl we're dealing with. If we find a libdumbnet, we prefix
dnl compat/libdnet to our inclusion path. It provides a dnet.h
dnl that transparently includes dumbnet.h for those systems. --CPK.
AC_MSG_CHECKING([whether libdnet is a libdumbnet])
if test `echo $DNETLIB | sed -e '/dumb/=;d'`; then
     AC_MSG_RESULT(yes)
     AC_DEFINE(HAVE_DUMBNET, 1,
		[Define if our libdnet is a libdumbnet])
     DNETCOMPAT="compat/libdnet"
else
     AC_MSG_RESULT(no)
fi

AC_SUBST(DNETCOMPAT)
AC_SUBST(DNETINC)
AC_SUBST(DNETLIB)

if test -z "$DNETCOMPAT"
then
	CFLAGS="$DNETINC"
else
	CFLAGS="-I$DNETCOMPAT $DNETINC"
fi
LIBS=$DNETLIB

dnl Checks for libevent
AC_MSG_CHECKING(for libevent)
AC_ARG_WITH(libevent,
[  --with-libevent=DIR     use libevent build directory],
[ case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     AC_MSG_RESULT($withval)
     if test -f $withval/event.h -a -f $withval/libevent.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
        EVENTINC="-I$withval"
        EVENTLIB="-L$withval -levent"
     else
        AC_MSG_ERROR(event.h or libevent.a not found in $withval)
     fi
     ;;
  esac ],
[ if test -f ${prefix}/include/event.h; then
     EVENTINC="-I${prefix}/include"
     EVENTLIB="-L${prefix}/lib -levent"
  elif test -f /usr/include/event/event.h; then
     EVENTINC="-I/usr/include/event"
     EVENTLIB="-levent"
  elif test -f /usr/include/event.h; then
     EVENTLIB="-levent"
  else
     AC_MSG_RESULT(no)
     AC_MSG_ERROR(libevent not found)
  fi
  AC_MSG_RESULT(yes) ]
)
AC_SUBST(EVENTINC)
AC_SUBST(EVENTLIB)

CFLAGS=$EVENTINC
LIBS=$EVENTLIB

CFLAGS=""
LIBS=""

AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(fcntl.h sys/ioctl.h sys/time.h unistd.h)

havesysselect=no
AC_CHECK_HEADER(sys/select.h, [havesysselect=yes], )
if test $havesysselect = yes; then
 AC_MSG_CHECKING([for fd_mask in sys/select.h])
 AC_EGREP_HEADER(fd_mask, sys/select.h,
  [ AC_DEFINE(HAVE_FDMASK_IN_SELECT)
    AC_MSG_RESULT([yes])], AC_MSG_RESULT([no]))
fi
dnl Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_CHECK_TYPE(u_int64_t, unsigned long long)
AC_CHECK_TYPE(u_int32_t, unsigned int)
AC_CHECK_TYPE(u_int16_t, unsigned short)
AC_CHECK_TYPE(u_int8_t, unsigned char)

AC_MSG_CHECKING([for struct sockaddr_storage in sys/socket.h])
AC_EGREP_HEADER(sockaddr_storage, sys/socket.h,
	[ AC_DEFINE(HAVE_SOCKADDR_STORAGE)
	  AC_MSG_RESULT([yes])], AC_MSG_RESULT([no])
)
AC_MSG_CHECKING([for struct addrinfo in netdb.h])
AC_EGREP_HEADER(addrinfo, netdb.h,
	[ AC_DEFINE(HAVE_STRUCT_ADDRINFO)
	  AC_MSG_RESULT([yes])], AC_MSG_RESULT([no])
)
AC_MSG_CHECKING([for timeradd in sys/time.h])
AC_EGREP_CPP(yes,
[
#include <sys/time.h>
#ifdef timeradd
yes
#endif
],	[ AC_DEFINE(HAVE_TIMERADD)
	  AC_MSG_RESULT([yes])], AC_MSG_RESULT([no])
)
AC_MSG_CHECKING([for byte order of raw socket I/O])
AC_EGREP_CPP(yes,
[
#include <sys/param.h>
#ifdef BSD4_4
  yes
#endif
], 
	AC_EGREP_CPP(yes,
	[#include <sys/param.h>
	 #ifdef OpenBSD
	   yes
	 #endif
	],
		AC_MSG_RESULT([good byte order]),
			[ AC_DEFINE(BSD_RAWSOCK_ORDER)
			  AC_MSG_RESULT([bad byte order])
                        ]
          ),
	  AC_MSG_RESULT([good byte order])
)
	
AC_MSG_CHECKING([for sin_len in struct sockaddr_in])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
 #include <sys/types.h>
 #include <sys/socket.h>
 #include <netinet/in.h>]], [[void *p = &((struct sockaddr_in *)0L)->sin_len;]])],[ AC_MSG_RESULT([yes])
    AC_DEFINE(HAVE_SIN_LEN, 1, [struct sockaddr_in contains sin_len]) ],[AC_MSG_RESULT(no)
])

AC_MSG_CHECKING([for sa_family_t])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
 #include <sys/types.h>
 #include <sys/socket.h>]], [[sa_family_t x;]])],[AC_MSG_RESULT(yes)],[AC_MSG_RESULT([no])
  AC_DEFINE(sa_family_t, int)
])

AC_MSG_CHECKING([for socklen_t])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
 #include <sys/types.h>
 #include <sys/socket.h>]], [[socklen_t x;]])],[AC_MSG_RESULT(yes)],[AC_MSG_RESULT([no])
  AC_DEFINE(socklen_t, int)
])

AC_MSG_CHECKING([for NI_NUMERICHOST])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
 #include <sys/types.h>
 #include <sys/socket.h>
 #include <netdb.h>]], [[char x[NI_NUMERICHOST];]])],[AC_MSG_RESULT(yes)],[AC_MSG_RESULT([no])
  AC_DEFINE(NI_NUMERICHOST, 1)
  AC_DEFINE(NI_MAXHOST, 256)
])

AC_MSG_CHECKING([for NI_MAXSERV])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
 #include <sys/types.h>
 #include <sys/socket.h>
 #include <netdb.h>]], [[char x[NI_MAXSERV];]])],[AC_MSG_RESULT(yes)],[AC_MSG_RESULT([no])
  AC_DEFINE(NI_MAXSERV, 32)
])

AC_CHECK_FUNCS(gettimeofday select socket strdup strerror strtol seteuid)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
