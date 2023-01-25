CC= gcc
CFLAGS=-g -march=x86-64
headers = common.h crt.h gmh.h gpa.h vfr.h vpr.h wpm.h
sources = apihook.c apiswatter.c common.c wpm.c gpa.c gmh.c crt.c vfr.c vpr.c dll_common.c
objects=$(sources:%.c=%.o)
all: apiswatter.exe apihook.dll
	@echo "ALL DONE"

apiswatter.exe: apiswatter.o common.o $(headers)
	$(CC) $(CFLAGS) -o apiswatter.exe apiswatter.o common.o -lShlwapi

apihook.dll : apihook.o common.o wpm.o gpa.o gmh.o crt.o vfr.o vpr.o dll_common.o $(headers)
	$(CC) -shared -o apihook.dll apihook.o common.o wpm.o gpa.o gmh.o crt.o vfr.o vpr.o dll_common.o -lShlwapi

clean:
	del *.exe
	del *.dll
	del *.o

