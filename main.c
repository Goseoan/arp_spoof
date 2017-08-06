#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arp_spoof.h"

int main(int argc, char *argv[])
{

  u_int8_t mac[MAC_ADDR_SIZE];        // my mac
  u_int8_t ip[IP_ADDR_SIZE];        // my ip
  u_int8_t router[IP_ADDR_SIZE];     // router ip
  u_int8_t *ifname;          // interface name
  u_int8_t *targetIP;    // target ip
  u_int8_t targetMAC[MAC_ADDR_SIZE];    // target mac

  if (argc < 3) 
  {
    puts("Usage: ./a.out <interface> <target ip address>");
    exit(1);
  }

  ifname    = argv[1];
  targetIP  = argv[2];
 // targetMAC = argv[3];
/*  gi->targetIP = *argv[2];
  gi->targetMAC = *argv[3];*/
  
  printf("\nInput Value ---------------------------------- \n \
    - Interface \t: %s \n \
    - Target IP \t: %s \n \
    ----------------------------------------- \n"   
    ,ifname,targetIP);

  getLocalAddress(ifname, ip, mac, router);

                                  
  printf("\nGet Local Information ------------------------ \n \
    - IP ADDR    \t: %s \n \
    - MAC ADDR   \t: %s \n \
    - ROUTER ADDR\t: %s \n \
    ----------------------------------------- \n"                                            
    ,ip,mac,router);

  arp_request(ifname, ip, mac, targetIP, targetMAC);   
  arp_spoof(ifname, ip, mac, router, targetIP, targetMAC); 

  return 0;
}
