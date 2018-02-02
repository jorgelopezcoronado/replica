/*
 * ethernet.h define ethernet structure for getting packet headers
 */


#define ETHERNET_HEADER_SIZE 14

#define ETHERNET_IPv4_TYPE ntohs(0x0800)
#define ETHERNET_IPv6_TYPE ntohs(0x86DD)

typedef struct ethernet_tag
{
#define ETHER_ADDR_LEN	6
	u_char ether_dhost[ETHER_ADDR_LEN]; //dest ether address
	u_char ether_shost[ETHER_ADDR_LEN]; //dest ether address
	u_short ether_type; //payload type
} ethernet_h;
