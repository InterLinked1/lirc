#
# LIRC - IRC Client Library for C
#
# Copyright (C) 2023, Naveen Albert
#

CC		= gcc
CFLAGS = -Wall -Werror -Wunused -Wextra -Wmaybe-uninitialized -Wstrict-prototypes -Wmissing-prototypes -Wdeclaration-after-statement -Wmissing-declarations -Wmissing-format-attribute -Wnull-dereference -Wformat=2 -Wshadow -Wsizeof-pointer-memaccess -std=gnu99 -pthread -O3 -g -Wstack-protector -fno-omit-frame-pointer -fwrapv -D_FORTIFY_SOURCE=2
EXE		= irc
LIBNAME = libirc
RM		= rm -f
INSTALL = install

all: library

library: irc.o
	@echo "== Linking $@"
	$(CC) -shared -fPIC -o $(LIBNAME).so $^ -lssl -lcrypto

libinstall: library
	$(INSTALL) -m  755 $(LIBNAME).so "/usr/lib"
	mkdir -p /usr/include/lirc
	$(INSTALL) -m 755 *.h "/usr/include/lirc/"

install: library libinstall

client : client.o
	$(CC) $(CFLAGS) -o $(EXE) $< -lirc

%.o : %.c
	$(CC) $(CFLAGS) -fPIC -c -Wno-unused-result $^

clean :
	$(RM) *.i *.o $(EXE)

uninstall:
	$(RM) /usr/lib/$(LIBNAME).so
	$(RM) /usr/include/lirc/*.h
	rm -rf /usr/include/lirc

.PHONY: all
.PHONY: install
.PHONY: clean
