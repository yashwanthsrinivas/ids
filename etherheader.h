//ether header

struct etherheader { 

  u_int8_t destinationaddress[6];
  u_int8_t sourceaddress[6];
  u_int16_t ethertype ; }; 


extern struct etherheader * ether;
