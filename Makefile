
BASEDIR = /usr/bin
INSTPATH = $(BASEDIR)/sqredir
CONFPATH = /etc/sqredir.conf

CFLAGS ?= -pipe -std=c99 -Wall -O2
COPY = cp -i
STRIP = strip
MKDIR = mkdir -p

sqredir: sqredir.c
	$(CC) $(CFLAGS) -o sqredir sqredir.c
	$(STRIP) sqredir

install: sqredir urls.txt
	$(MKDIR) $(BASEDIR)
	$(COPY) sqredir $(INSTPATH)
	$(COPY) sqredir.conf.dist $(CONFPATH)

clean: 
	rm -f sqredir *~
