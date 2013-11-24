
BASEDIR = /usr/bin
INSTPATH = $(BASEDIR)/sqredir
CONFPATH = /etc/sqredir.conf

CFLAGS ?= -pipe -std=c99 -Wall -O2
COPY = cp -i
STRIP = strip
MKDIR = mkdir -p

sqredir: blocklist.h blocklist.c match.h match.c sqredir.c
	$(CC) $(CFLAGS) -o sqredir blocklist.c match.c sqredir.c
	$(STRIP) sqredir

install: sqredir urls.txt
	$(MKDIR) $(BASEDIR)
	$(COPY) sqredir $(INSTPATH)
	$(COPY) sqredir.conf.dist $(CONFPATH)

clean: 
	rm -f sqredir *~
