
#ifndef bsnmp_config_h_
#define bsnmp_config_h_


#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#define HAVE_GETADDRINFO  1
#define HAVE_STDINT_H     1
#define OPENSSL_SYS_WIN32 1

#define ssize_t    int
#define socket_t    SOCKET

#define vsnprintf   _vsnprintf
#define strtoll     _strtoi64
#define strtoull    _strtoui64
#define random      rand
#define strncasecmp _strnicmp
#define strcasecmp  _stricmp

#define MAXPATHLEN  MAX_PATH

#ifndef __func__
#define __func__ __FUNCTION__
#endif

#ifndef __unused
#define __unused
#endif

#else

#define socket_t    int

#define closesocket close

#ifndef MAXPATHLEN
#define MAXPATHLEN 1024
#endif

#endif


#define HAVE_LIBCRYPTO 1

#endif
