#
# Makefile
#

# target name
TARGET=security_plugin.so

# source files
FILES=security_plugin.c

# compiler
CC=gcc

# flags
FLAGS=-std=gnu99 -Wall -Wextra


build: ${TARGET}


# install, root only
install: build
	cp ${TARGET} /usr/local/libexec


# uninstall, root only
uninstall:
	rm -f /usr/local/libexec/${TARGET}


# clean
clean:
	rm -f *.o ${TARGET}


${TARGET}: ${FILES}
	${CC} ${FILES} -o ${TARGET} ${FLAGS}


