# Send_ARP

This Program is Arp Spoofing Example Source Code    

Souce Code Composition is arp_spoof.h arp_spoof.c main.c Makefile     

arp_spoof.h is function protype & #define value    
arp_sppof.c is      
1. Get Local Information IPv4 Address, MAC addresss, Router Address    
2. Send ARP REQUEST and get Target MAC Address    
3. Send ARP SPOOFING to target spoof arp table of router mac to my mac     

## Enviroment
- Kali Linux     
- gcc     
- pcap library     

## Compile 
```
make
```
## Get local value

mac is socket   
router , ip address is bash


