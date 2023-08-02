service = aa
WIN_CD = $(shell powershell -c 'pwd | select-object  -expandproperty path')
LIN_CD = $(shell pwd)
WIN_COMP	= x86_64-w64-mingw32-g++.exe
LIN_COMP	= x86_64-w64-mingw32-g++-win32
TARGET		= main
default: build setup # Windows only
build:
ifeq ($(SystemDrive),C:)
	$(WIN_COMP) -w -o $(TARGET).exe src/main.cpp src/windivert.h src/WinDivert.lib
else
	$(LIN_COMP) -w -o $(TARGET).exe src/main.cpp src/windivert.h src/WinDivert.lib
endif
setup: # Windows only
	sc create $(service) binPath= "$(WIN_CD)\main.exe"
	sc start $(service)
rm:
	sc delete $(service)
	sc stop $(service)
	taskkill /f /fi "SERVICES eq $(service)"
clean:
ifeq ($(SystemDrive),C:)
	del "$(WIN_CD)\main.exe" /f
else
	rm -rf "$(LIN_CD)/main.exe"
endif