/*
 * dns.h: header file to specifiy DNS packet structure
 */
typedef struct dns_header_t_tag
{
	u_short id;
	u_short flags;
	u_short query_count;
	u_short answer_count;
	u_short auth_servers_count;
	u_short additional_records_count;
}dns_header_t;
/*
 * The following functions and flags depend on system arch!!! check this later.
 */
#define DNS_QR(dns_header)	(((dns_header)->flags & 0x0080) >> 7) //DNS query-response 
#define DNS_OC(dns_header)	(((dns_header)->flags & 0x0078) >> 3) //DNS Opcode: 0 std query, 1 obsolete, 2 status, 3 NOT USED, 4 notify, 5 update
#define DNS_OC_STD_QUERY	0
#define DNS_OC_INV_QUERY	1 //obsolete!
#define DNS_OC_STATUS		2
#define DNS_OC_RESERVED		3 //should this be here?
#define DNS_OC_NOTIFY		4
#define DNS_OC_UPDATE		5
#define DNS_AA(dns_header)	(((dns_header)->flags & 0x0004) >> 2) //DNS authoritative answer
#define DNS_TC(dns_header)	(((dns_header)->flags & 0x0002) >> 1) //DNS truncated message flag
#define DNS_RD(dns_header)	((dns_header)->flags & 0x0001) // DNS recursion desired
#define DNS_RA(dns_header)	(((dns_header)->flags & 0x8000) >> 15) //DNS recursion available
#define DNS_Z(dns_header)	(((dns_header)->flags & 0x7000) >> 12) //DNS DNS Zero(0)
#define DNS_RC(dns_header)	(((dns_header)->flags & 0x0F00) >> 8) //DNS response code, 0 no error, 1 format error, 2 server failure, 3 name error, 4 not implemented, 5 refused, 6 yxdomain, 7 yxrrdomain, 8 nxrrdomain, 9 not auth, 10 notzone
#define DNS_RC_NOERROR		0
#define DNS_RC_FORMATERROR	2
#define DNS_RC_SERVERFAIL	2
#define DNS_RC_NAMEERROR	3
#define DNS_RC_NOTIMPL		4 
#define DNS_RC_REFUSED		5
#define DNS_RC_YXDOMAIN		6
#define DNS_RC_YXRRDOMAIN	7
#define DNS_RC_NXRRDOMAIN	8
#define DNS_RC_NOTAUTH		9
#define DNS_RC_NOTZONE		10

typedef struct dns_query_t_tag
{
	u_char *name; //will be represented as standard DNS notation, constans can be transformed once, but, will benefit of not having to always transform all packets.
	u_short type;
	u_short class;
}dns_query_t;
//Only the most common values
#define DNS_Q_TYPE_A 1
#define DNS_Q_TYPE_NS 2
#define DNS_Q_TYPE_CNAME 5
#define DNS_Q_TYPE_SOA 6
#define DNS_Q_TYPE_PTR 12
#define DNS_Q_TYPE_MX 15
#define DNS_Q_TYPE_TXT 16
//Only one common value for class
#define DNS_Q_CLASS_IN 1

typedef struct dns_resource_record_t_tag
{
	u_char *name; //will be represented as standard DNS notation, constans can be transformed once, but, will benefit of not having to always transform all packets.
        u_short type;
        u_short class;
	u_int TTL;
	u_short data_length;
	u_char *data; //data will be treated as a bit stream, don't really care about message particular formats ATM.
}dns_resource_record_t;

typedef struct dns_packet_tag
{
	dns_header_t *header;
	linked_list *queries; //list of dns_query_t
	linked_list *answers; //list of dns_resource_record_t
	linked_list *auth_servers; //list of dns_resource_record_t
	linked_list *additional_records; //list of dns_resource_record_t
}dns_packet;
