PROG=	myserver
SRCS=	main.c myserver.c

DPADD+=	${LIBSYS}
LDADD+=	-lsys
#LDADD+= ../../../../obj.i386/crypto/external/bsd/openssl/lib/libssl/libssl.a
#LDADD+= ../../../../obj.i386/crypto/external/bsd/openssl/lib/libcrypto/libcrypto.a

#LDADD+= ../../../../obj.i386/lib/libc/libc.a

# FIXME: workaround for the linker pass not seeing weak symbols. The
# following symbols are essential for magic instrumentation, since they
# perform memory de/allocation. For some reason, their weak versions are
# not picked up by the linker in the first (instrumentation) pass. With
# these definitions we force the first pass to include them.
CPPFLAGS.myserver.c+= -Dregcomp=_regcomp -Dregfree=_regfree

.include <minix.service.mk>
