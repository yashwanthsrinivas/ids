// TCP Header 

typedef u_int tcp_seq ;
 
struct tcpheader {    

  u_short sourceport;               /* source port */
  u_short destinationport;               /* destination port */
  tcp_seq seq;                 /* sequence number */
  tcp_seq ack;                 /* acknowledgement number */
  u_char  offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->offx2 & 0xf0) >> 4)
  u_char  flags;
#define FIN  0x01
#define SYN  0x02
#define RST  0x04
#define PUSH 0x08
#define ACK  0x10
#define URG  0x20
#define ECE  0x40
#define CWR  0x80
#define FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short window;                 /* window */
  u_short checksum;                 /* checksum */
  u_short urgptr;                 /* urgent pointer */
};


  
