all: tcpping

uninstall: remove

tcpping: tcpping.c
	gcc -Wall -g tcpping.c -o tcpping -lnet -lpcap

install:
	install -m 4755 ./tcpping /usr/bin/tcpping

remove:
	rm -f /usr/bin/tcpping

clean:
	rm -f tcpping
