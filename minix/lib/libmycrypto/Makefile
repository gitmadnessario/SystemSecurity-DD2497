# Makefile for libmycrypto

LIB=	mycrypto

SRCS=	mycrypto.c

# DPADD+= ${LIBCRYPTO} ${LIBSSL} ${LIBC}
# LDADD+= -lcrypto -lssl -lc

CPPFLAGS+= -I@srcdir@../../../crypto/external/bsd/openssl/dist/crypto

.include <bsd.lib.mk>
