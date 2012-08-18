
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
#define vsnprintf  _vsnprintf


#ifndef __func__
#define __func__ __FUNCTION__
#endif

#ifndef __unused
#define __unused
#endif

#else

#define closesocket close

#endif


#define HAVE_LIBCRYPTO 1

#endif
