#include<stdio.h>
#include<pcap/pcap.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<string.h>
#include<net/ethernet.h>
#include<netinet/ether.h>

struct etheraddr{
  u_int8_t addr[6] ; };

struct etherheader{
  //u_int8_t sourceaddr[ETH_ALEN];
  //u_int8_t destinationaddr[ETH_ALEN] ;
  //u_int16_t ethernettype ;}; 
  struct etheraddr sourceaddr;
  struct etheraddr destinationaddr ;
  u_int16_t ethertype ; };


void printeverything(char * packet)
{ int i=0;
  printf("Packet Raw  details "); 
  for (; packet[i]!=NULL ; i++)
    printf("%c",packet[i]); } 
                                                   


struct tcpheader { 
  u_int16_t sourceport ;
  u_int16_t destinationport ;
  u_int32_t seq;
  u_int32_t ack_seq;
  u_int16_t doff;
  u_int16_t res1;
  u_int16_t res2 ;
  u_int16_t urg;
  u_int16_t ack;
  u_int16_t psh;
  u_int16_t rst ;
  u_int16_t syn;
  u_int16_t fin ;
}mytcp ;

struct ipheader { 
  unsigned int version;
  unsigned int headerlenght ;
  u_int8_t typeofservice ;
  u_short totallength ;
  u_short identification ;
  u_short fragmentoffsetfield; 
#define reservedfrag 0x8000;
#define dontfrag 0x4000 ;
#define morefrag 0x2000;
#define frag 0x1fff;
  u_int8_t timetolive;
  u_int8_t protocol ; 
  u_short checksum ; 
  struct in_addr sourceaddr;
  struct in_addr destinationaddr ; 
} myip ;


/*CALLBACK FUNCTION */

void mycallback( char * args ,  struct   pcap_pkthdr * mypkt ,  u_char * data ) 
{ //printf("---------------------------------------\ncaptured length : %d \n  packet length : %d \n" ,  mypkt->caplen, mypkt->len );
  struct etherheader * myethernet ;
  struct tcpheader * mytcp; 
  struct ipheader * myip ;
  char * datagram;
  myethernet=data;
  myip=data+sizeof(struct etherheader);
  mytcp=data+sizeof(struct ipheader) +  sizeof(struct etherheader);
  datagram=data+sizeof(struct etherheader)+sizeof(struct tcpheader)+sizeof(struct ipheader);

  printeverything(data);
  printf("\n\n");





  
  printf("\n\n******************************************************Dtalink Layer Details***********************************************************************\n");
  //struct etheraddr * source ; source=myethernet->sourceaddr;
  //struct etheraddr * destination ; destination->addr=myethernet->destinationaddr;
  printf("Mac source address : %s\n",ether_ntoa(&(myethernet->sourceaddr)));
  printf("Mac destination address : %s\n",ether_ntoa(&(myethernet->destinationaddr)));
  printf("Mac type : %d\n",myethernet->ethertype );





  printf("*****************************************************Network Layer details*************************************************************************\n");
  printf("IP version number %d\n",myip->version);
  printf("IP headerlenght %d\n",myip->headerlenght);
  printf("IP type of service %d\n",myip->typeofservice );
  printf("IP identifcation : %d\n",myip->identification);
  printf("IP fragmentoffsetfield : %d\n",myip->fragmentoffsetfield);
  printf("IP time to live : %d \n" , myip->timetolive );
  printf("IP protocol :  %d \n", myip->protocol);
  printf("IP checksum %d\n", myip->checksum ) ; 
  printf("IP source address : %s\n ", inet_ntoa(myip->sourceaddr));
  printf("IP destination address : %s\n\n ", inet_ntoa(myip->destinationaddr));






  printf("***************************************************** TCP/IP Layer details *****************************************************************************\n");
  printf("TCP source port : %d \n" ,mytcp->sourceport );
  printf("TCP destination port : %d\n" , mytcp->destinationport );
  printf("TCP seq : %d \n", mytcp->seq);
  printf("TCP ack_seq : %d \n", mytcp->ack_seq);
  printf("TCP data offset %d\n",mytcp->doff);
  printf("TCP res1 %d \n", mytcp->res1);                     
  printf("TCP res2 %d \n", mytcp->res2);
  printf("TCP urg %d\n", mytcp->urg);
  printf("TCP ack %d\n",mytcp->ack);
  printf("TCP psh %d\n",mytcp->psh);
  printf("TCP rst %d \n", mytcp->rst);
  printf("TCP syn %d \n", mytcp->syn);
  printf("TCP fin %d \n\n", mytcp->fin);
  printf("*********************************************************************************************************************************************************");
    } 



int main(int argc , char ** argv ){
  if(argc==1){printf("Enter the interface too U ass !");return -1;}
  char iface[4];
  strcpy(iface,argv[1]);
  char *er;
  pcap_t * ihandle=pcap_open_live(iface,25,0,10,er);
  if(ihandle==NULL)perror("pcap_open_live:");
  struct pcap_pkthdr * pcapheader;
  struct ether_header * eheader;
  int no=5;
  char * pktdata;
  printf("Interface is %s\n",iface);
  struct bpf_program  mybpf ; 
  char * fil=argv[2];
  printf("The filter is %s\n",fil);
   bpf_u_int32 nm = 0;
   int opt=0;
   int cmp;
   if((cmp=pcap_compile( ihandle , &mybpf , fil , opt , nm  ))==0)printf("Compiling perfect . compile return value %d \n",cmp);else  printf("compiling error : %s ... compile return value %d\n",pcap_geterr(ihandle),cmp);
     if(pcap_setfilter(ihandle , &mybpf )==0)printf("Filter set properly");
     perror("after loop");
  pcap_loop(ihandle , -1 , mycallback , NULL);
  printf("%s\n",pcap_geterr(ihandle)); 
      return 0;}

