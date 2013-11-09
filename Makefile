# injcode/Makefile
#
CXXFLAGS=-g -W -Wall -pipe -O2
GIT=git
ECHO=echo
SED=sed
GZIP=gzip
TAR=tar
GPG=gpg

#ARCH=ia32
ARCH=x86_64

all: injcode

injcode: injcode.o \
inject.o \
retty.o \
testmodule.o \
closemodule.o \
dup2module.o \
shellcode-test-linux-$(ARCH).o \
shellcode-close-linux-$(ARCH).o \
shellcode-dup2-linux-$(ARCH).o \
shellcode-retty-linux-$(ARCH).o
	$(CXX) $(CXXFLAGS) -o $@ $^ -lutil

injcode-%.tar.gz:
	$(GIT) archive --format=tar \
		--prefix=$(shell $(ECHO) $@ | $(SED) 's/\.tar\.gz//')/ \
		injcode-$(shell $(ECHO) $@|$(SED) 's/.*-//'|$(SED) 's/\.tar\.gz//') \
		| $(TAR) --delete injcode-$(shell $(ECHO) $@|$(SED) 's/.*-//'|$(SED) 's/\.tar\.gz//')/.be  | $(GZIP) -9 > $@
	$(GPG) -b -a $@

pt:
	g++ -Wall -W -g -o pt pt.cc shellcode-linux-$(ARCH).S -lutil
b.s:
	gcc -c -g -Wa,-a,-ad b.c > b.lst

clean:
	rm -f *.o injcode
