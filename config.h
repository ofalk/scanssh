/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */
/* Define if your raw sockets have arguments in host order as in BSD.  */
/* #undef BSD_RAWSOCK_ORDER */

/* Define if your system knows about struct sockaddr_storage */
#define HAVE_SOCKADDR_STORAGE 1

/* Define to int if your system does not know about sa_family_t */
/* #undef sa_family_t */

/* Define to int if your system does not know about socklen_t */
/* #undef socklen_t */

/* Define to `unsigned long long' if <sys/types.h> doesn't define.  */
/* #undef u_int64_t */

/* Define to `unsigned int' if <sys/types.h> doesn't define.  */
/* #undef u_int32_t */

/* Define to `unsigned short' if <sys/types.h> doesn't define.  */
/* #undef u_int16_t */

/* Define to `unsigned char' if <sys/types.h> doesn't define.  */
/* #undef u_int8_t */

/* Undefine if <netdb.h> contains this, otherwise define to 1 */
/* #undef NI_NUMERICHOST */

/* Undefine if <netdb.h> contains this, otherwise define to 1 */
/* #undef NI_MAXHOST */

/* Undefine if <netdb.h> contains this, otherwise define to 32 */
/* #undef NI_MAXSERV */

/* Take care of getaddrinfo */
#define HAVE_STRUCT_ADDRINFO 1

/* Define if timeradd is defined in <sys/time.h> */
#define HAVE_TIMERADD 1
#ifndef HAVE_TIMERADD
#define timeradd(tvp, uvp, vvp)                                         \
        do {                                                            \
                (vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;          \
                (vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;       \
                if ((vvp)->tv_usec >= 1000000) {                        \
                        (vvp)->tv_sec++;                                \
                        (vvp)->tv_usec -= 1000000;                      \
                }                                                       \
        } while (0)
#define	timersub(tvp, uvp, vvp)						\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_usec += 1000000;			\
		}							\
	} while (0)
#endif /* !HAVE_TIMERADD */

/* Define if fd_mask is defined in <sys/select.h> */
#define HAVE_FDMASK_IN_SELECT 1

/* Define to 1 if you have the `arc4random' function. */
#define HAVE_ARC4RANDOM 1

/* Define if our libdnet is a libdumbnet */
/* #undef HAVE_DUMBNET */

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the `getaddrinfo' function. */
#define HAVE_GETADDRINFO 1

/* Define to 1 if you have the `getnameinfo' function. */
#define HAVE_GETNAMEINFO 1

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* Define to 1 if you have the `inet_aton' function. */
#define HAVE_INET_ATON 1

/* Define to 1 if you have the `inet_pton' function. */
#define HAVE_INET_PTON 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `iphlpapi' library (-liphlpapi). */
/* #undef HAVE_LIBIPHLPAPI */

/* Define to 1 if you have the `nsl' library (-lnsl). */
/* #undef HAVE_LIBNSL */

/* Define to 1 if you have the `socket' library (-lsocket). */
/* #undef HAVE_LIBSOCKET */

/* Define to 1 if you have the `ws2_32' library (-lws2_32). */
/* #undef HAVE_LIBWS2_32 */

/* Define to 1 if you have the `MD5Update' function. */
/* #undef HAVE_MD5UPDATE */

/* Define to 1 if you have the `select' function. */
#define HAVE_SELECT 1

/* Define to 1 if you have the `seteuid' function. */
#define HAVE_SETEUID 1

/* struct sockaddr_in contains sin_len */
/* #undef HAVE_SIN_LEN */

/* Define to 1 if you have the `socket' function. */
#define HAVE_SOCKET 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcat' function. */
/* #undef HAVE_STRLCAT */

/* Define to 1 if you have the `strlcpy' function. */
/* #undef HAVE_STRLCPY */

/* Define to 1 if you have the `strsep' function. */
#define HAVE_STRSEP 1

/* Define to 1 if you have the `strtol' function. */
#define HAVE_STRTOL 1

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have <sys/wait.h> that is POSIX.1 compatible. */
#define HAVE_SYS_WAIT_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the `warnx' function. */
#define HAVE_WARNX 1

/* Name of package */
#define PACKAGE "scanssh"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME ""

/* Define to the full name and version of this package. */
#define PACKAGE_STRING ""

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME ""

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION ""

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE void

/* Define to 1 if all of the C90 standard headers exist (not just the ones
   required in a freestanding environment). This macro is provided for
   backward compatibility; new code need not use it. */
#define STDC_HEADERS 1

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. This
   macro is obsolete. */
#define TIME_WITH_SYS_TIME 1

/* Version number of package */
#define VERSION "2.1.3"

/* Define for faster code generation. */
/* #undef WIN32_LEAN_AND_MEAN */

/* Define as a signed integer type capable of holding a process identifier. */
/* #undef pid_t */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Use MingW32's internal snprintf */
/* #undef snprintf */

/* Define to `unsigned short' if <sys/types.h> does not define. */
/* #undef u_int16_t */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef u_int32_t */

/* Define to `unsigned long long' if <sys/types.h> does not define. */
/* #undef u_int64_t */

/* Define to `unsigned char' if <sys/types.h> does not define. */
/* #undef u_int8_t */
