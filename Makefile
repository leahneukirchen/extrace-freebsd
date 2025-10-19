PROG=	extrace

WARNS?=	6
LDADD=	-lkvm

PREFIX?=	/usr/local
BINDIR?=	$(PREFIX)/bin
MANDIR?=	$(PREFIX)/share/man/man

.include <bsd.prog.mk>
