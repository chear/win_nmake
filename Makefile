.PHONY:all clean
CFLAGS=-ansi -Wall -pedantic -std=c99 
LFLAGS=-lm 
GCC=gcc
Q=@

.PHONY:ctags
ctags:
	ctags --langmap=c:+.h --extras=+q --if0=no -o c_tags -R 

.PHONY:linux
linux:
	echo "building ./mac_generator for linux"
	$(GCC) $(CFLAGS) -c ap_mac_generator.c 
	$(GCC) -o mac_generator ap_mac_generator.o




WINCC = cl
WIN_CFLAGS = -I
.PHONY:win
win:
	 nmake makefile.MAK

