// IP Header

/* struct ipheader {
  unsigned int headerlength ;
  unsigned int version;
  u_int8_t typeofservice ;
  u_int16_t totallength;
  u_int16_t identification;

#ifndef IP_RF 
#define IP_RF 0x8000;
#endif
 
#ifndef IP_DF 
#define IP_DF 0x4000;
#endif

#ifndef IP_MF
#define IP_MF 0x2000;
#endif

#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff;
#endif

    u_int16_t fragmentoffset ;
  u_int8_t timetolive ;
  u_int8_t protocol ;
  u_int16_t checksum;
  struct in_addr sourceaddress ;
  struct in_addr destinationaddress ;
};   */



struct ipheader { 

  u_int8_t  headerversion; 
  u_int8_t typeofservice ;
  u_int16_t totallength ;
  u_int16_t identification;
  u_int16_t fragmentoffset ;
  u_int8_t timetolive ;
  u_int8_t protocol ;
  u_int16_t checksum;
  struct in_addr sourceaddress ;
  struct in_addr destinationaddress ;  
  //#define IP_RF 0x8000; 
  //#define IP_DF 0x4000;
  //#define IP_MF 0x2000;
  //#define IP_OFFMASK 0x1fff ;

}; 
#define ipversionmacro(ip)  (  (ip->headerversion ) >> 4  )
#define ipheadermacro(ip)  ( ( ip->headerversion )  & 0x0F ) 


