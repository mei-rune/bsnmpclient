

#include "bsnmp/config.h"
#include <stdio.h>
#include <errno.h>


#ifndef HAVE_INET_NTOP

#ifndef NS_INT16SZ      
#define NS_INT16SZ      2
#endif
#ifndef NS_INADDRSZ  
#define NS_INADDRSZ     4
#endif
#ifndef NS_IN6ADDRSZ  
#define NS_IN6ADDRSZ    16
#endif
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT    WSAEAFNOSUPPORT
#endif
#ifndef ENOSPC          
#define ENOSPC          28
#endif

static const char *inet_ntop4(const unsigned char *src, char *dst, size_t size) {
    const char *fmt = "%u.%u.%u.%u";
    char tmp[sizeof "255.255.255.255"];
    size_t len;

    len = snprintf(tmp, sizeof tmp, fmt, src[0], src[1], src[2], src[3]);

    if (len >= size) {
        errno = ENOSPC;
        return (NULL);
    }
    memcpy(dst, tmp, len + 1);

    return (dst);
}

#ifdef AF_INET6
static const char *inet_ntop6(const unsigned char *src, char *dst, size_t size) {
    char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], *tp;
    struct {
        int base, len;
    } best, cur;
    unsigned int words[NS_IN6ADDRSZ / NS_INT16SZ];
    int i, inc;

    memset(words, '\0', sizeof words);
    for (i = 0; i < NS_IN6ADDRSZ; i++)
        words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
    best.base = -1;
    cur.base = -1;
    for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
        if (words[i] == 0) {
            if (cur.base == -1)
                cur.base = i, cur.len = 1;
            else
                cur.len++;
        } else {
            if (cur.base != -1) {
                if (best.base == -1 || cur.len > best.len)
                    best = cur;
                cur.base = -1;
            }
        }
    }
    if (cur.base != -1) {
        if (best.base == -1 || cur.len > best.len)
            best = cur;
    }
    if (best.base != -1 && best.len < 2)
        best.base = -1;


    tp = tmp;
    for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
        if (best.base != -1 && i >= best.base &&
                i < (best.base + best.len)) {
            if (i == best.base)
                *tp++ = ':';
            continue;
        }
        if (i != 0)
            *tp++ = ':';
        if (i == 6 && best.base == 0 &&
                (best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
            if (!inet_ntop4(src+12, tp, sizeof tmp - (tp - tmp)))
                return (NULL);
            tp += strlen(tp);
            break;
        }
        inc = snprintf(tp, 5, "%x", words[i]);
        tp += inc;
    }
    if (best.base != -1 && (best.base + best.len) ==
            (NS_IN6ADDRSZ / NS_INT16SZ))
        *tp++ = ':';
    *tp++ = '\0';

    if ((size_t)(tp - tmp) > size) {
        errno = ENOSPC;
        return (NULL);
    }
    memcpy(dst, tmp, tp - tmp);
    return (dst);
}
#endif /* AF_INET6 */

const char *inet_ntop(int af, const void *src, char *dst, size_t size) {
    switch (af) {
    case AF_INET:
        return (inet_ntop4((const unsigned char*)src, dst, size));
#ifdef AF_INET6
    case AF_INET6:
        return (inet_ntop6((const unsigned char*)src, dst, size));
#endif
    default:
        errno = EAFNOSUPPORT;
        return (NULL);
    }
}

#endif
