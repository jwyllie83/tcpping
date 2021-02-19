PREFIX ?=
PACKAGE=tcpping_1.0

all: tcpping manpage

uninstall: remove

tcpping: tcpping.c
	$(CC) -Wall -g tcpping.c -o tcpping $(CFLAGS) -lnet -lpcap

manpage: tcpping.1.xml
	xmltoman tcpping.1.xml | gzip > tcpping.1.gz

install: all
	mkdir -p $(PREFIX)/usr/bin
	install -m 4755 ./tcpping $(PREFIX)/usr/bin
	mkdir -p $(PREFIX)/usr/share/man/man1
	install -m 644 ./tcpping.1.gz $(PREFIX)/usr/share/man/man1/tcpping.1.gz

deb: all
	mkdir -p $(PACKAGE)
	cp -r DEBIAN $(PACKAGE)/DEBIAN
	mkdir -p $(PACKAGE)/usr/bin
	install -m 4755 ./tcpping $(PACKAGE)/usr/bin
	mkdir -p $(PACKAGE)/usr/share/man/man1
	install -m 644 ./tcpping.1.gz $(PACKAGE)/usr/share/man/man1/tcpping.1.gz
	cp LICENSE $(PACKAGE)/DEBIAN/copyright
	dpkg-deb -b $(PACKAGE) $(PACKAGE).deb

remove:
	rm -f $(PREFIX)/usr/bin/tcpping
	rm -f $(PREFIX)/usr/share/man/man1/tcpping.1.gz

clean:
	rm -f ./tcpping ./tcpping.1.gz
