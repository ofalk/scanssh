/* Define if your raw sockets have arguments in host order as in BSD.  */
#undef BSD_RAWSOCK_ORDER

/* Define if your system knows about struct sockaddr_storage */
#undef HAVE_SOCKADDR_STORAGE

/* Define to int if your system does not know about sa_family_t */
#undef sa_family_t

/* Define to int if your system does not know about socklen_t */
#undef socklen_t

/* Define to `unsigned long long' if <sys/types.h> doesn't define.  */
#undef u_int64_t

/* Define to `unsigned int' if <sys/types.h> doesn't define.  */
#undef u_int32_t

/* Define to `unsigned short' if <sys/types.h> doesn't define.  */
#undef u_int16_t

/* Define to `unsigned char' if <sys/types.h> doesn't define.  */
#undef u_int8_t

/* Undefine if <netdb.h> contains this, otherwise define to 1 */
#undef NI_NUMERICHOST

/* Undefine if <netdb.h> contains this, otherwise define to 1 */
#undef NI_MAXHOST

/* Undefine if <netdb.h> contains this, otherwise define to 32 */
#undef NI_MAXSERV

/* Take care of getaddrinfo */
#undef HAVE_STRUCT_ADDRINFO

/* Define if timeradd is defined in <sys/time.h> */
#undef HAVE_TIMERADD
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
#undef HAVE_FDMASK_IN_SELECT
