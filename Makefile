
INSTDIR = /usr/bin
CONFPATH = /etc/sqredir.conf

CFLAGS ?= -pipe -std=c99 -Wall -O2
COPY = cp
STRIP = strip
MKDIR = mkdir -p

sqredir: blocklist.h blocklist.c match.h match.c sqredir.c
	$(CC) $(CFLAGS) -o sqredir blocklist.c match.c sqredir.c

install: sqredir
	$(STRIP) sqredir
	$(MKDIR) $(INSTDIR)
	# DO overwrite the binary
	$(COPY) -f sqredir $(INSTDIR)
	# DO NOT overwrite an existing configuration
	$(COPY) -n sqredir.conf.dist $(CONFPATH)

clean: 
	rm -f sqredir *~
