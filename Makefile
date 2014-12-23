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
FLAGS=-std=gnu99
CFLAGS=-fPIC
LDFLAGS=-shared


build: ${TARGET}


# install, root only
install: build
	cp ${TARGET} /usr/local/libexec


# uninstall, root only
uninstall:
	rm -f /usr/local/libexec/${TARGET}


# clean
clean:
	rm -rf obj *.o ${TARGET}


${TARGET}: ${FILES}
	${CC} ${FILES} ${FLAGS} ${CFLAGS} ${LDFLAGS} -o ${TARGET}
