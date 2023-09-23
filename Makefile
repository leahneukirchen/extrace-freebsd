ALL=extrace

CFLAGS=-g -O2 -Wall -Wno-switch -Wextra -Wwrite-strings
LDFLAGS=-lkvm

DESTDIR=
PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
MANDIR=$(PREFIX)/man


all: $(ALL)

README: extrace.1
	mandoc -Wall -Ios=OpenBSD -Tutf8 $< | col -bx >$@

clean: FRC
	rm -f $(ALL)

install: FRC all
	mkdir -p $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man1
	install -m0755 $(ALL) $(DESTDIR)$(BINDIR)
	install -m0644 $(ALL:=.1) $(DESTDIR)$(MANDIR)/man1

FRC:
