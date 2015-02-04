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
DFLAGS=-Wall -Wextra -Wp,-D_FORTIFY_SOURCE=2 -O2


build: ${TARGET}

# install, root only
install: build
	cp ${TARGET} ${OUTPUT2}
	#[ -e "/etc/sudo.conf" ] && mv -f /etc/sudo.conf /etc/sudo.conf.bak
	echo "Plugin sudoers_policy security_plugin.so" > /etc/sudo.conf


# uninstall, root only
uninstall:
	rm -f /usr/local/libexec/${TARGET}
	rm -rf /etc/sudo_security_plugin/
	#[ -e "/etc/sudo_security_plugin.conf" ] && rm -f /etc/sudo_security_plugin.conf
	#[ -e "/etc/sudo_security_plugin.conf~" ] && rm -f /etc/sudo_security_plugin.conf~
	rm -f /etc/sudo.conf
	#[ -e "/etc/sudo.conf.bak" ] && mv -f /etc/sudo.conf.bak /etc/sudo.conf


# clean
clean:
	rm -rf obj *.o ${TARGET}


${TARGET}: ${FILES}
	${CC} ${FILES} ${FLAGS} ${DFLAGS} -o ${TARGET}
