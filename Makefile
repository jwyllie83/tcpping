all: tcpping

tcpping: tcpping.c
	gcc -Wall -g tcpping.c -o tcpping -lnet -lpcap

clean:
	rm -f tcpping
