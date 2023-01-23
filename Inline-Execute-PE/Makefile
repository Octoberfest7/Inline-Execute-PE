all: peload perun peunload

peload: peload.c
	x86_64-w64-mingw32-gcc -c peload.c -o peload.x64.o -Llibucrtbase.a -DBOF -Os -m64

perun: perun.c
	x86_64-w64-mingw32-gcc -c perun.c -o perun.x64.o -DBOF -Os

peunload: peunload.c
	x86_64-w64-mingw32-gcc -c peunload.c -o peunload.x64.o -DBOF -Os

oldrun: oldrun.c
	x86_64-w64-mingw32-gcc -c oldrun.c -o oldrun.x64.o -DBOF -Os