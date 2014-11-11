all:
	gcc gentable.c aes.c -o gentable
	gcc crack.c aes.c -o crack
clean:
	rm gentable
	rm crack