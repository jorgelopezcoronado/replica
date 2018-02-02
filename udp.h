/*
 * udp.h header file that defines UDP structure
 */

#define UDP_HEADER_SIZE 8

typedef struct sniff_udp
{
	u_short uh_sport; /* source port */
	u_short uh_dport; /* destination port */
	u_short uh_length; /* packet length */ 
	u_short uh_sum; /* checksum */
}udph;
