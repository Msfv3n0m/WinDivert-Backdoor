# WinDivert-Backdoor
## Build
### Codespaces/Devcontainer
Just run `make`! </br>
You can export the exe by running `python3 -m http.server` and opening the web page in a browser
### Linux
```
sudo apt install mingw-w64 -y && \
sudo apt install make -y
```
Then just run `make`!
### Windows
1. Download [mingw64](https://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/8.1.0/threads-win32/seh/x86_64-8.1.0-release-win32-seh-rt_v6-rev0.7z)
2. Download and install [7zip](https://www.7-zip.org/a/7z2301-x64.exe)
3. Select Extract Here
4. Add `C:\mingw64\bin` to the system's PATH environment variable
5. Run this `move C:\mingw64\bin\mingw32-make.exe to C:\mingw64\bin\make.exe`
6. Just run `make`! 
### VSCode 
1. Install [VSCode](https://code.visualstudio.com/download)
2. Get the `ms-vscode.cpptools` extension for intellisense and debugging

## Usage
### Compatibility
This project is compatible with Win7, Win8, Win10, WS2012, and WS2016
### Server
1. Copy WinDivert.dll and WinDivert64.sys to C:\Windows\System32 folder 
2. Install driver with [GDRVLoader.exe](https://github.com/zer0condition/GDRVLoader) </br>
`GDRVLoader.exe \Windows\System32\WinDivert64.sys` 
3. Install service </br>
`sc create WinDivertService binPath= "C:\path\to\main.exe" start= auto` </br>
`sc description WinDivertService "this is a description"`
5. Start service </br>
`sc start WinDivertService`
6. (Optional) Install [rootkit](https://github.com/bytecode77/r77-rootkit) </br>
`Install.exe`
### Client
1. Install python and pip
2. Install [nmap](https://nmap.org/download#windows)
3. Download client.py script
4. Install requirements with [the official docs](https://scapy.readthedocs.io/en/latest/installation.html) or with this command: </br>
`pip install -R requirements.txt` </br>
5. Flourish

## Issues
The windows service doesn't exit properly, so you have to kill the process (as shown in the makefile)
## References
| Link to Project                                                                  | Code Used?      | License                                                                                              |
|----------------------------------------------------------------------------------|-----------------|------------------------------------------------------------------------------------------------------|
| https://github.com/zer0condition/GDRVLoader                                      | No              | None                                                                                                 |
| https://github.com/basil00/Divert                                                | Yes             | GNU Lesser General Public License Version 3 or the GNU General Public License Version 2              |
| https://www.codeproject.com/Articles/499465/Simple-Windows-Service-in-Cplusplus  | Yes             | The Code Project Open License (CPOL) 1.02                                                            |
| https://github.com/r-a303931/pcap-backdoor                                       | No              | GNU Affero General Public License v3.0                                                               |
| https://github.com/bytecode77/r77-rootkit                                        | No              | BSD 2-Clause "Simplified" License                                                                    |
