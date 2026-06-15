all: myELF

myELF: myELF.c
	gcc -m32 -g -Wall -o myELF myELF.c

clean:
	rm -f myELF