PROG=extrace

LDADD+=-lkvm
CFLAGS+=-Wall -Wno-switch -Wextra -Wwrite-strings

.include <bsd.prog.mk>
