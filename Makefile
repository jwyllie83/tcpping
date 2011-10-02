all: tcpping manpage

uninstall: remove

tcpping: tcpping.c
	gcc -Wall -g tcpping.c -o tcpping -lnet -lpcap

manpage: tcpping.1.xml
	xmltoman tcpping.1.xml | gzip > tcpping.1.gz

install:
	install -m 4755 ./tcpping /usr/bin/tcpping
	mkdir -p /usr/share/man/man1
	install -m 644 ./tcpping.1.gz /usr/share/man/man1/tcpping.1.gz

remove:
	rm -f /usr/bin/tcpping

clean:
	rm -f ./tcpping ./tcpping.1.gz
