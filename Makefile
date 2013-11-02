all:	loader

loader: loader.c loader.h
	#gcc -g -Wformat=false -o loader loader.c
	gcc -g -Wformat=false loader.c -o libloader.so -Wl,-soname=libloader.so -shared -fPIC -Wall -m32
	
clean:
	rm -f loader *.o *.swp *.so *~
