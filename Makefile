CC= gcc
CFLAGS=-g -march=x86-64
headers = 
sources = apiswatter.c apihook.c common.c
objects=$(sources:%.c=%.o)
all: apiswatter.exe apihook.dll
	@echo "ALL DONE"

apiswatter.exe: apiswatter.o common.o $(headers)
	$(CC) $(CFLAGS) -o apiswatter.exe apiswatter.o common.o -lShlwapi

apihook.dll : apihook.o common.o $(headers)
	$(CC) -shared -o apihook.dll apihook.o common.o -lShlwapi

clean:
	del *.exe
	del *.dll
	del *.o

