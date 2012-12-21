#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<time.h>
#include<sys/types.h>

int  pcapfilemake( char * packetdata , int packetlength) { 
 
  char date[20];
  system("mkdir ./pcap.pcap ;  echo ' pcap.pcap dir contains the pcap files \n' ");
  time_t currenttime=time(NULL);
  struct tm * timestruct = localtime(&currenttime);
  char * format="%F-%m";
  strftime(date ,20,format ,timestruct);
  FILE * pcapfile ;
  char filename[30]="./pcap.pcap/pcap";
  strcat(filename,date);
  strcat(filename,".pcap");
  if ( (pcapfile =fopen(filename,"w+")) >0 )  printf(" %s created successfully \n",filename);
  //fprintf(pcapfile,"%s\n",packetdata);                                                                                         
  //fputs(packetdata,pcapfile);
  fwrite(packetdata, packetlength , 1, pcapfile ); 
 
  return 1 ;

}
