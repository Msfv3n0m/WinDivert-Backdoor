service = aaaaaa
P = C:\Users\Administrator\Downloads\new-divert\MinGW-Devcontainer-main
build:
	x86_64-w64-mingw32-g++.exe -o main.exe src/main.cpp src/windivert.h src/WinDivert.lib
	sc create $(service) binPath= "$(P)\main.exe"
	sc start $(service)
# x86_64-w64-mingw32-g++.exe -o main.exe main.o -L lib -municode
del:
	sc delete $(service)
	sc stop $(service)
clean:
	rm -rf main.exe