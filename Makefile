CC?=		clang
AR?=		ar
INSTALL?=	install
PREFIX?=	/usr/local
CFLAGS?=	-O2

all: fortuna

fortuna:

	$(CC) -c -fPIC -I. $(CFLAGS) -g -Wall -Werror ./src/fortuna.c ./src/rijndael.c ./src/sha2.c ./src/px.c
	$(AR) rvs libfortuna.a fortuna.o rijndael.o sha2.o px.o
	$(CC) -shared -fPIC -o libfortuna.so fortuna.o rijndael.o sha2.o px.o

clean:
	rm -f *.a
	rm -f *.o
	rm -f *.so

install:
	mkdir $(PREFIX)/include/fortuna
	$(INSTALL) -m 644 ./src/fortuna.h $(PREFIX)/include/fortuna/
	$(INSTALL) -m 644 ./src/px.h $(PREFIX)/include/fortuna/
	$(INSTALL) -m 644 ./src/rijndael.h $(PREFIX)/include/fortuna/
	$(INSTALL) -m 644 ./src/sha2.h $(PREFIX)/include/fortuna/
	$(INSTALL) -m 644 ./src/c.h $(PREFIX)/include/fortuna/
	$(INSTALL) -m 644 ./libfortuna.a $(PREFIX)/lib/
	$(INSTALL) -m 644 ./libfortuna.so $(PREFIX)/lib/

deinstall:
	rm -Rf $(PREFIX)/include/fortuna
	rm -f $(PREFIX)/lib/libfortuna.a
	rm -f $(PREFIX)/lib/libfortuna.so

