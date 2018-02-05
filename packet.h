/*
 * runmon.h: define runmun structures
 */
#include "linked_list.h"
#include "ethernet.h"
#include "ip4.h"
#include "tcp.h"
#include "udp.h"
#include "sip.h"
#include "dns.h"
#include <openssl/bio.h>

#define CURRENT_STATUS_FAIL -1
#define CURRENT_STATUS_PASS 1
#define CURRENT_STATUS_INCONCLUSIVE 0

#define SIP_PORT 5060
#define DNS_PORT 53

typedef enum transport_e_tag
{
	TCP = 0,	
	UDP = 1	
}transport_e;

typedef enum protocol_e_tag
{
	SIP = 0,
	DNS = 1
}protocol_e;

typedef enum stream_state_tag
{
	INIT = 0,
	A_TV_SEC_L = 1,
	A_TV_SEC = 2,
	A_TV_USEC_L = 3,
	A_TV_USEC = 4,
	A_CAPLEN = 5,
	A_LEN = 6
}stream_state_e;

typedef struct runmon_packet_tag
{
	ethernet_h *ethernet;
	ip4 *ip;
	void *transport;
	void *protocol;
	transport_e transport_type;
	protocol_e protocol_type;
	struct timeval *time; 	
	int location_in_trace;
	int reference_count;
	int associations;
	char *PO;
	linked_list *dependencies;
	BOOL *completed_properties;
	struct pcap_pkthdr *pkthdr;
	u_char *data;
}runmon_packet;

typedef struct report_status_t_tag
{
	unsigned long period;
	unsigned int properties_count;
}report_status_t;

typedef struct serve_conn_t_tag
{
	BIO *bio;
	int buffersize;
	int properties_count;
}serve_conn_t;
