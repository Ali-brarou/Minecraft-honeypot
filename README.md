# Minecraft Honeypot

A lightweight C-based Minecraft honeypot designed to detect and log status ping requests from annoying scanners and bots. 
This tool implements the basic Minecraft handshake and status protocol, responding with a fake server status and logging client information. 

For security reasons, Please avoid running this as a privileged or personel user.
Instead, it's better to use a container or create new non-privileged user

The fake status text and other config are hardcoded in src/global.h

## Requirements 
- GCC (should work for clang)
- Unix-based system 
- make (optional)

## Build 
''' 
git clone https://github.com/Ali-brarou/Minecraft-honeypot.git
cd Minecraft-honeypot/src/
make
'''

## Run 
./minecraft-honey

## References 
https://minecraft.wiki/w/Java_Edition_protocol/
https://minecraft.wiki/w/Java_Edition_protocol/Server_List_Ping
