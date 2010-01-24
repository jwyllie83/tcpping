all: tcpping

tcpping: tcpping.c
	gcc -Wall -g tcpping.c -o tcpping -lnet -lpcap -O0

clean:
	rm -f tcpping
