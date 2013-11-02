all: testaddsub testhello testvar

%.o: %.c hello.h
	gcc -m32 -o $@ -c $<

testaddsub: testaddsub.o addsub.o
	gcc -m32 -g -o testaddsub testaddsub.o libloader.so -Wl,-rpath,.

testhello: testhello.o hello.o
	gcc -m32 -g -o testhello testhello.o libloader.so -Wl,-rpath,.

testvar: testvar.o var.o
	gcc -m32 -g -o testvar testvar.o libloader.so -Wl,-rpath,.

test: all
	./testaddsub
	./testhello
	./testvar

clean:
	rm -f *.o testaddsub testhello testvar
