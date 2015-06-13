#
# Makefile
#

# target name
TARGET=security_plugin.so

# source files
FILES=security_plugin.c

OUTPUT1=/usr/local/libexec
OUTPUT2=/usr/libexec/sudo

# compiler
CC=gcc

# flags
FLAGS=-std=gnu99 -lpam -lpam_misc -fPIC -shared
#-D_FORTIFY_SOURCE=2
DFLAGS=-Wall -Wextra

build: ${TARGET}

# install, root only
install: build
	cp ${TARGET} ${OUTPUT2}
	mkdir /var/lib/sudo_security_plugin
	mv -f /etc/sudo.conf /etc/sudo.conf.bak
	echo "Plugin sudoers_policy security_plugin.so" > /etc/sudo.conf


# uninstall, root only
uninstall:
	rm -f /usr/local/libexec/${TARGET}
	rm -rf /var/lib/sudo_security_plugin/
	rmdir /var/lib/sudo_security_plugin/
	mv -f /etc/sudo.conf.bak /etc/sudo.conf


# clean
clean:
	rm -rf obj *.o ${TARGET}


${TARGET}: ${FILES}
	${CC} ${FILES} ${FLAGS} ${DFLAGS} -o ${TARGET}
