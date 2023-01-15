#
# LIRC - IRC Client Library for C
#
# Copyright (C) 2023, Naveen Albert
#

CC		= gcc
CFLAGS = -Wall -Werror -Wunused -Wextra -Wmaybe-uninitialized -Wstrict-prototypes -Wmissing-prototypes -Wdeclaration-after-statement -Wmissing-declarations -Wmissing-format-attribute -Wnull-dereference -Wformat=2 -Wshadow -Wsizeof-pointer-memaccess -std=gnu99 -pthread -O0 -g -Wstack-protector -fno-omit-frame-pointer -fwrapv -D_FORTIFY_SOURCE=2
EXE		= irc
RM		= rm -f
INSTALL = install

MAIN_SRC := $(wildcard *.c)
MAIN_OBJ = $(MAIN_SRC:.c=.o)

all: $(MAIN_OBJ)
	$(CC) $(CFLAGS) -o $(EXE) *.o -lssl -lcrypto

%.o : %.c
	$(CC) $(CFLAGS) -c $^

clean :
	$(RM) *.i *.o $(EXE)

.PHONY: all
.PHONY: install
.PHONY: clean
