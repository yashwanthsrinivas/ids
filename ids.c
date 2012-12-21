                                                         // Network Intrusion Detection System 

#include<stdlib.h>
#include<string.h>
#include<stdio.h>
#include<arpa/inet.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<netinet/in.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<getopt.h>
#include<pcap.h>
#include<net/ethernet.h>

#include"ipheader.h"
#include"tcpheader.h"
#include"etherheader.h"
#include"pcapfilemake.h"

struct ipheader * ip;
struct tcpheader * tcp ; 
struct etherheader * ether ; 
char errbuff[20];
int returnvalue ,noofpackets,caplen;
char filter[10],interface[10];
int i;
void pcapcallback( char * args , struct pcap_pkthdr * pcappkthdr , u_char * data ) {
  i=0;

  /*  printf("\n++++++++++++++++++++++++++++++++++++++++++++++++++Actual Data in Hex +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
  for ( ; i<pcappkthdr->len ; i++ ) printf("%.2X",data[i]) ;
printf (" Packet length is %d \n" , pcappkthdr->len );
  ether=(struct etherheader * ) data ;
  ip=(struct ipheader *) ( data + sizeof(struct etherheader ) ) ; 
  tcp=(struct tcpheader * ) ( data + sizeof (struct etherheader) + ipheadermacro(ip)*4  );
 
   
  printf("\n                                                      ETHERNET DETAILS \n"
	 "  Destination MAC Address  : %d:%d:%d:%d:%d:%d \n "
	  "  Source MAC Address       : %d:%d:%d:%d:%d:%d \n "
	  " Ethernet Type %d \n" , ether->destinationaddress[0],ether->destinationaddress[1], ether->destinationaddress[2] , ether->destinationaddress[3], ether->destinationaddress[4] , ether->destinationaddress[5] , ether->sourceaddress[0] , ether->sourceaddress[1] , ether->sourceaddress[2],  ether->sourceaddress[3], ether->sourceaddress[4], ether->sourceaddress[5] , ether->ethertype );
  
   
    printf("                                                         IP Details \n");
  printf(" Header Length %d \n"
	 " Version number %d \n " 
	 " Type of service %d \n "
	 " Total Length %d \n"                                 
	 " Identification %d \n"
	 " fragment offset %d \n "
	 "Time to live %d  \n"                               
	 "Protocol %d \n" 
	 "Checksum %d  \n"
	 " Source IP Address %s \n" 
	 " Destination IP Address %s\n"   , (ipheadermacro(ip)) *4  , ipversionmacro(ip) , ip->typeofservice , ntohs(ip->totallength) , ntohs(ip->identification) , ip->fragmentoffset , ip->timetolive , ip->protocol , ntohs(ip->checksum) , inet_ntoa( ip->sourceaddress )  , inet_ntoa( ip->destinationaddress  )  );
 
switch(ip->protocol ) {
  case(IPPROTO_TCP):printf("Packet for the TCP Layer\n");break;
  case(IPPROTO_IP):printf("Packet for the IP layer\n");exit(1);
  //case(IPPROTO_ARP)printf("Packet for the ARP layer\n");break;
  case(IPPROTO_UDP):printf("Packet for the UDP layer\n");break;     
 case(IPPROTO_ICMP):printf("Packet for the ICMP layer\n");break;
  default:printf("NO MATCHING TYPES\n");break;   } 
	 

    printf("                                                            TCP Details\n");
  printf(" source port %d \n " 
	 " Destination port %d \n\n"  , ntohs( tcp->sourceport ) , ntohs ( tcp->destinationport ) );
  //  printf("------------------------------------------------------------------------------------------------------------------");  
  */
             
  pcapfilemake(data,pcappkthdr->len);

} // END OF CALLBACK




int main(int argc , char ** argv ){                 
  system("/usr/bin/clear");
  while(1)
    {
      int optionindex = 0 ;
      static struct option optionlist[10]=
       {
	 {"noofpackets",required_argument,0,'n' } ,
	 { "filter", required_argument , 0, 'f' } ,
	 {"verbose",no_argument, 0, 'v'  } ,
	 { "interface",required_argument , 0 ,'i'} ,
	 {"caplen",required_argument,0,'l'} ,
	 {0,0,0,0 }
       };

     returnvalue=getopt_long(argc , argv , "n:f:i:l:v" , optionlist  , &optionindex );
     if(returnvalue==-1)break;
     switch(returnvalue) {

     case 'v' :
       printf("\n\n\n *************** This is a simple Intrusion Detection System ************************\n\n\n");
       break;

     case 'i' :
       //printf("Interface is %s \n ", optarg );                                                                                                               
      strcpy(interface,optarg );
       break ;

     case 'f' :
       //printf("Filter is %s \n  ", optarg );                                                                                                                         
       strcpy(filter,optarg );
       break;
     case 'n' :
       //printf("No of packets to be captured : %d \n  ", atoi(optarg) );                                                                                              
       noofpackets=atoi(optarg);                                                 
       break;
     case 'l':
       caplen=atoi(optarg);
       break;

     default :
       exit(1) ;
     }}
  int comp;
  pcap_t * handle ; 
  handle=pcap_open_live(interface,caplen,0,-1,errbuff);
  struct bpf_program bp;
  bpf_u_int32 netmask=0;
  if((pcap_compile(handle,&bp,filter,0,netmask))!=0) printf("%s",pcap_geterr(handle) ) ;
  
  if(pcap_setfilter(handle ,&bp)!=0) printf("%s",pcap_geterr(handle) );
   printf("\n\nCapture Starting... \n");

   // printf("no of packets %d ", noofpackets);

  if(pcap_loop(handle , noofpackets , pcapcallback , NULL)<0) printf(" %s",pcap_geterr(handle) );
 
  
     return 1 ; }
  
  

  

