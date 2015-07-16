#
# Makefile
#

# target name
TARGET=security_plugin.so

# source files
FILES=security_plugin.c utils.c command.c io.c

OUTPUT=/usr/libexec/sudo

# compiler
CC=gcc

# flags
FLAGS=-std=gnu11 -lpam -lpam_misc -fPIC -shared

build: ${TARGET}

# reinstall, root only
reinstall: build
	cp ${TARGET} ${OUTPUT}

# install, root only
install: build
	cp ${TARGET} ${OUTPUT}
	mkdir /var/lib/sudo_security_plugin
	if test -f /etc/sudo.conf; then mv -f /etc/sudo.conf /etc/sudo.conf.bak; fi
	echo "Plugin sudoers_policy security_plugin.so" > /etc/sudo.conf
	echo "#Dual authorisation security plugin configuration file" > /etc/sudo_security_plugin.conf
	gzip -c manpage > /usr/share/man/man8/dual-authorization.8.gz

# uninstall, root only
uninstall:
	rm -f /etc/sudo.conf
	if test -f /etc/sudo.conf.bak; then mv -f /etc/sudo.conf.bak /etc/sudo.conf; fi
	rm -f /etc/sudo_security_plugin.conf
	if test -f /etc/sudo_security_plugin.conf?; then rm -f /etc/sudo_security_plugin.conf?; fi
	rm -f /usr/local/libexec/${TARGET}
	rm -f /usr/share/man/man8/dual-authorization.8.gz
	rm -rf /var/lib/sudo_security_plugin
	rm -rf obj *.o ${TARGET}

# clean
clean:
	rm -rf obj *.o ${TARGET}


${TARGET}: ${FILES}
	${CC} ${FILES} ${FLAGS} -o ${TARGET}
