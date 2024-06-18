PROG=extrace

LDADD+=-lkvm
CFLAGS+=-Wall -Wno-switch -Wextra -Wwrite-strings

PREFIX?=/usr/local
BINDIR?=$(PREFIX)/bin
MANDIR?=$(PREFIX)/share/man/man

.include <bsd.prog.mk>
