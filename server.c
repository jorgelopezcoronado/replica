/*
 * extmon.c: main file for the extmon client tool
 * 		the idea behind this client is to capture packets and 
 * 		forward them using a network protocol that resembles 
 * 		exactly to the structure of pcap to an external monitoring
 * 		host.
 *
 */
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <pcap.h>
#include "helpers.h" 
#include "runmon.h" 

#define MAX_PORT_NUM 65535
#define PENDING_CONNS_Q 10

#define DEBUG 1

#define CRLF "\r"

int debug;

void init_ssl()
{
	//load standard init functions for SSL
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
}

report_error(char *message, char *content)
{
    printf(message, content);
    printf("Error: %s\n", ERR_reason_error_string(ERR_get_error()));
    printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
}

SSL_CTX *setup_SSL_CTX(char *certificate_file, char* private_key_file) //consider adding chain files here... no, but, really consider it...
{
	SSL_CTX *ctx = SSL_CTX_new(SSLv23_method()); 
	if (!ctx)
        {
                report_error("Unable to allocate SSL context pointer.\n", NULL);
                return NULL;
        }	
	if(SSL_CTX_use_certificate_file(ctx, certificate_file, SSL_FILETYPE_PEM) <= 0)
	{
		report_error("Unable to load certificate file %s\n", certificate_file);
		SSL_CTX_free(ctx);		
		return NULL;
	}
	if(SSL_CTX_use_PrivateKey_file(ctx, private_key_file, SSL_FILETYPE_PEM) <= 0)
	{
		report_error("Unable to load certificate file %s\n", certificate_file);
		SSL_CTX_free(ctx);		
		return NULL;
	}
	//Alright, at this point I should take care of adding chain files, but, for now, let's just check if key corresponds to cert
	if (!SSL_CTX_check_private_key(ctx))
	{
		report_error("Private key file does not correspond to specified certificate\n", NULL);
		SSL_CTX_free(ctx); 
                return NULL;
	}

	//should I return ctx? maybe I can return a bio and in fact place ssl and ctx in sent pointers... will check this later...
	return ctx;
}

ssize_t read_from_stream(BIO *bio, char *buffer, ssize_t length)
{
	ssize_t read_bytes = -3;
	
	while(read_bytes < 0)
	{
		read_bytes = BIO_read(bio, buffer, length);
		
		//if read_bytes positive or 0 either we read some bytes or we reached the end of the stream which is normal behavior
		if(read_bytes < 0 && !BIO_should_retry(bio)) //there was an error as per documentation If BIO_should_retry() is false then the cause is an error condition.
		{
			report_error("Read error, BIO_should_retry error\n", NULL);
			return read_bytes;
		}

		//at this point the loop will continue only if read_bytes < 0 and no error on BIO_should_retry, so cool, otherwise the condition will not be satisfied and we'll be good 
	}

	return read_bytes;
}

ssize_t write_to_stream(BIO *bio, char *buffer, ssize_t length)
{
	ssize_t written_bytes = -3;
	
	while (written_bytes < 0)
	{
		written_bytes = BIO_write(bio, buffer, length);
		
		if (written_bytes < 0 && !BIO_should_retry(bio))
		{
			report_error("Write error, BIO_should_retry error\n", NULL);
			return written_bytes;
		}
	}
	
	return written_bytes;
}

int open_listener(struct in_addr *IP_addrr, int port)
{
	int socket_descriptor;
	struct sockaddr_in *addrr = (struct sockaddr_in*)malloc(1 * sizeof(struct sockaddr_in));
	int pending_conns_q = PENDING_CONNS_Q; //perhaps in the future as a param -> userconf?

	if (port < 0 || port >= MAX_PORT_NUM)
		return -1;
	
	socket_descriptor = socket(PF_INET, SOCK_STREAM, 0);
	
	if (socket_descriptor < 0)
	{
		report_error("Couldn't create socket descriptor\n", NULL);
		free(addrr);
		return -1;
	}
	
	addrr->sin_family = AF_INET;
	addrr->sin_port = htons(port);
	addrr->sin_addr = *IP_addrr;
	
	if(bind(socket_descriptor, (struct sockaddr*)addrr, sizeof(struct sockaddr_in)) != 0)
	{
		report_error("Can't bind port\n", NULL);
		free(addrr);
                return -1;
	}
	
	if(listen(socket_descriptor, pending_conns_q) != 0)
	{
		report_error("Can't configure listening port\n", NULL);
                free(addrr);
                return -1;
	}	
	// all work is done properly here.

	return socket_descriptor;
}

/**
 * create_string_from_text_payload: copies all data to a char* to manipulate the string
 * USEFUL for all TEXT BASED PROTOCOLS
 */

char *create_string_from_text_payload(char *payload, int size)
{
	
	char *string_form = (char*)malloc(size + 1);
	int i = 0;
	for (i; i < size; i++)
		*(string_form + i) = *(payload + i);
	*(string_form + i) = 0;
	return string_form;
}

void release_sip(sip_packet *sip)
{
	char *start_of_text = (sip->start_line->method)?sip->start_line->method:sip->start_line->version;
	free(start_of_text);
	free(sip->start_line);
	while(sip->header_fields->head)
		free(linked_list_delete(sip->header_fields));
	linked_list_delete(sip->header_fields);
	//not free sip->message_body, since message boddy is part of the main start of text when allocating.
	free(sip);
}

/*
 * proccess_sip: process the payload and convert it to a sip struct
 */

sip_packet *process_sip(u_char *payload, int payload_size)
{
	char* sip_text = create_string_from_text_payload(payload, payload_size);
	char *message_body, *temp_string;
	char *start_line_text = strtok_r(sip_text, CRLF, &message_body);
	int size = 0, i = 0;
	char *save_ptr = NULL;
	start_line_s *message_start_line =(start_line_s*)malloc(sizeof(start_line_s)); 
	linked_list *header_fields = create_linked_list();
	linked_list *header_fields_text = create_linked_list();
	sip_packet *sip = (sip_packet*)malloc(sizeof(sip_packet));	
	void *header_field_value;

#define MIN_SIP_TEXT_LENGTH 7 //at least if should have SIP/x.y version in the string text, else this is a corrupt package.

	if(strlen(sip_text) < MIN_SIP_TEXT_LENGTH)
	{
		free(sip_text);
		free(message_start_line);
		linked_list_delete(header_fields);	
		linked_list_delete(header_fields_text);
		free(sip);
		return NULL;
	}

	while (temp_string  = strtok_r(NULL, CRLF, &message_body))
	{	
		//Since splitting will leave \n at the begining I'll remove this \n
		if(*temp_string == '\n') temp_string++;
		//When only a newline is present, futher removed, that means the body message is up next.
		if (strcmp(temp_string, "") == 0) break;
		//here I just make sure folding won't affect my application
		if (!isspace(*temp_string)) 
			linked_list_add(header_fields_text, temp_string);
		else //I need to add the content to the previous header field
			strcat(((char*)linked_list_get(header_fields_text)), temp_string);
	}
	
	temp_string = strtok_r(start_line_text, " ", &save_ptr);

	if(strcasecmp(temp_string, "REGISTER") == 0 || strcasecmp(temp_string, "INVITE") == 0 || strcasecmp(temp_string, "ACK") == 0 || strcasecmp(temp_string, "CANCEL") == 0 || strcasecmp(temp_string, "BYE") == 0 || strcasecmp(temp_string, "OPTIONS") == 0 || strcasecmp(temp_string, "SUBSCRIBE") == 0 || strcasecmp(temp_string, "NOTIFY") == 0 ) // http://tools.ietf.org/html/rfc3261#page-26 request methods definition and extension http://www.ietf.org/rfc/rfc3265.txt
	{

		message_start_line->method = temp_string;	
		message_start_line->request_URI = strtok_r(NULL, " ", &save_ptr);
		message_start_line->version = save_ptr;
		message_start_line->status_code = 0;;
		message_start_line->reason_phrase = NULL;
	}
	else // it is status line actually
	{
		message_start_line->method= NULL;
		message_start_line->request_URI = NULL;
		message_start_line->version = temp_string;
		message_start_line->status_code = (short)atoi(strtok_r(NULL, " ", &save_ptr));
		message_start_line->reason_phrase = save_ptr;
	}

	if (linked_list_transverse(header_fields_text, &header_field_value))
	{
		header_field *headerfield = (header_field*)malloc(sizeof(header_field) * 1);
		headerfield->name = strtok_r((char*)header_field_value, ":", (char**)&headerfield->value);
		strtrim(&headerfield->name);
                strtrim(&headerfield->value);
                linked_list_add(header_fields, headerfield);
	}
	while (linked_list_transverse(NULL, &header_field_value))	
	{
		header_field *headerfield = (header_field*)malloc(sizeof(header_field) * 1);
		headerfield->name = strtok_r((char*)header_field_value, ":", (char**)&headerfield->value);
		strtrim(&headerfield->name);
		strtrim(&headerfield->value);
		linked_list_add(header_fields, headerfield);
	}
	delete_linked_list(header_fields_text);

	strtrim(&message_body);

	sip->start_line = message_start_line;
	sip->header_fields = header_fields;
	sip->message_body = message_body;

	return sip;
}

void print_sip(sip_packet *sip)
{
	int i = 0;
	void *header_field_value;
	linked_list *header_fields = sip->header_fields;
	
	if(!DEBUG)
		return;
	
	if (sip->start_line->method != NULL)
		printf("Method: %s Request_URI: %s Version: %s\n", sip->start_line->method, sip->start_line->request_URI, sip->start_line->version);
	else
		printf("Version: %s Status Code: %i Reason Phrase: %s\n", sip->start_line->version, sip->start_line->status_code, sip->start_line->reason_phrase);

	if(linked_list_transverse(sip->header_fields, &header_field_value))
	{
		header_field *headerfield = (header_field*)header_field_value;
		printf("%s->%s\n", headerfield->name, headerfield->value);
	}

	while (linked_list_transverse(NULL, &header_field_value))
        {
                header_field *headerfield = (header_field*)header_field_value;
                printf("%s->%s\n", headerfield->name, headerfield->value);
        }

	printf("\n%s\n", sip->message_body);
}



/*
 * process_dns_name: auxiliary function to 
 */
u_char *process_dns_name(u_char *payload, u_char **pointer)
{
        u_char *data_ptr = *pointer;
        int i = 0, chars = (int)*data_ptr, jump = 0, length = 0;
	u_char *result = NULL;

	if(((chars & 0xC0) >> 6) == 3)//fist two bits are on, we have a jump
	{
		jump = ((*data_ptr & 0x3F) << 8) + *(data_ptr + 1);
		data_ptr = payload + jump;
		chars = (int)*data_ptr;
		*pointer = *pointer + 2;
	}
	
	//if we are at this point it means we need to process the string
		
        while(chars)
        {    
		length += chars + 1;
		result = (u_char*)realloc(result, length * sizeof(u_char));
                for(i = 0; i <= chars; i++) 
                      *(result + length - (chars + 1) + i) = *(data_ptr++); 
		if(!jump)
			*pointer = *pointer + chars + 1;
                chars = (int)*data_ptr;
		if(((chars & 0xC0) >> 6) == 3)//fist two bits are on, we have a jump
        	{
			jump = ((*data_ptr & 0x3F) << 8) + *(data_ptr + 1);
			data_ptr = payload + jump;
               		chars = (int)*data_ptr;
		}
		else if(!jump && !chars)
			*pointer = *pointer + 1;
        }	
	length++;
	result = (u_char*)realloc(result, length * sizeof(u_char));
	*(result + length -1) = 0;

	return result;
}

/*
 * process_dns: function to map a packet to a dns_packet structure
 */
dns_packet *process_dns(u_char *payload, int payload_size)
{
	dns_packet *dns = (dns_packet*)malloc(1 * sizeof(dns_packet));
	dns->header = (dns_header_t*)payload;
	linked_list *queries = NULL, *answers = NULL, *auth_servers = NULL, *additional_records = NULL;
	dns_query_t *dns_query = NULL;
	dns_resource_record_t *dns_resource_record = NULL;
	u_char *ptr = payload + sizeof(dns_header_t);
	int i = 0;
	
	queries = create_linked_list();
	answers = create_linked_list();
	auth_servers = create_linked_list();
	additional_records = create_linked_list();

	for (i = 0; i < ntohs(dns->header->query_count); i++)
	{
		dns_query = (dns_query_t*)malloc(1 * sizeof(dns_query_t));
		dns_query->name = process_dns_name(payload, &ptr);		
		dns_query->type = *(u_short*)ptr;
		ptr = ptr + sizeof(u_short);
		dns_query->class = *(u_short*)ptr;
		ptr = ptr + sizeof(u_short);
		linked_list_add(queries, dns_query);
	}

	for (i = 0; i < ntohs(dns->header->answer_count); i++)
        {
		dns_resource_record = (dns_resource_record_t*)malloc(1 * sizeof(dns_resource_record_t));
		dns_resource_record->name = process_dns_name(payload, &ptr);		
		dns_resource_record->type = *(u_short*)ptr;
                ptr = ptr + sizeof(u_short);
		dns_resource_record->class = *(u_short*)ptr;
		ptr = ptr + sizeof(u_short);
		dns_resource_record->TTL = *(u_int*)ptr;
		ptr = ptr + sizeof(u_int);
		dns_resource_record->data_length = *(u_short*)ptr;
                ptr = ptr + sizeof(u_short);
                dns_resource_record->data = (u_char*)ptr;
                ptr = ptr + htons(dns_resource_record->data_length);
		linked_list_add(answers, dns_resource_record);
	}	
		
	for (i = 0; i < ntohs(dns->header->auth_servers_count); i++)
        {
                dns_resource_record = (dns_resource_record_t*)malloc(1 * sizeof(dns_resource_record_t));
                dns_resource_record->name = process_dns_name(payload, &ptr);
                dns_resource_record->type = *(u_short*)ptr;
                ptr = ptr + sizeof(u_short);
                dns_resource_record->class = *(u_short*)ptr;
                ptr = ptr + sizeof(u_short);
                dns_resource_record->TTL = *(u_int*)ptr;
                ptr = ptr + sizeof(u_int);
                dns_resource_record->data_length = *(u_short*)ptr;
                ptr = ptr + sizeof(u_short);
                dns_resource_record->data = (u_char*)ptr;
                ptr = ptr + htons(dns_resource_record->data_length);
               	linked_list_add(auth_servers, dns_resource_record);
        }

	for (i = 0; i < ntohs(dns->header->additional_records_count); i++)
        {
                dns_resource_record = (dns_resource_record_t*)malloc(1 * sizeof(dns_resource_record_t));
                dns_resource_record->name = process_dns_name(payload, &ptr);
                dns_resource_record->type = *(u_short*)ptr;
                ptr = ptr + sizeof(u_short);
                dns_resource_record->class = *(u_short*)ptr;
                ptr = ptr + sizeof(u_short);
                dns_resource_record->TTL = *(u_int*)ptr;
                ptr = ptr + sizeof(u_int);
                dns_resource_record->data_length = *(u_short*)ptr;
                ptr = ptr + sizeof(u_short);
                dns_resource_record->data = (u_char*)ptr;
		ptr = ptr + htons(dns_resource_record->data_length);
                linked_list_add(additional_records, dns_resource_record);
        }
	dns->queries = queries;	
	dns->answers = answers;
	dns->auth_servers = auth_servers;
	dns->additional_records = additional_records;

	return dns;
}

/*
 * release_dns: frees all memory resources of a DNS packet
 */

void release_dns(dns_packet *dns)
{
	//free(dns->header); //why this matching way won't get released? pointer already gone? 
	int i = 0;
	dns_query_t *query = NULL;
	dns_resource_record_t *resource_record = NULL;
	while(dns->queries->head != NULL)
        {
		query = linked_list_delete(dns->queries);
		free(query->name);
		free(query);
	}
	delete_linked_list(dns->queries);

	while(dns->answers->head != NULL)
        {
                resource_record = linked_list_delete(dns->answers);
                free(resource_record->name);
		//free(resource_record->data);
                free(resource_record);
        }
        delete_linked_list(dns->answers);

	while(dns->auth_servers->head != NULL)
        {
                resource_record = linked_list_delete(dns->auth_servers);
                free(resource_record->name);
		//free(resource_record->data);
                free(resource_record);
        }
        delete_linked_list(dns->auth_servers);

	while(dns->additional_records->head != NULL)
        {
                resource_record = linked_list_delete(dns->additional_records);
                free(resource_record->name);
		//free(resource_record->data);
                free(resource_record);
        }
        delete_linked_list(dns->additional_records);
	
	free(dns);
}

/*
 * print_std_dns_notation: auxiliary function to display data in standard DNS notation
 */
void print_std_dns_notation(u_char* data)
{
	u_char *data_ptr = data;
	int i = 0, chars = (int)*data_ptr;
	data_ptr++;
	while(chars)
	{
		for(i = 0; i < chars; i++)
			printf("%c",*(data_ptr + i));
		printf(".");
		data_ptr += chars;
		chars = (int)*data_ptr;
		data_ptr++;
	}
}


/*
 * print_dns: function to print a DNS record
 */
void print_dns(dns_packet *dns)
{
	linked_list_node *node = NULL;
        dns_query_t *dns_query = NULL;
        dns_resource_record_t *dns_resource_record = NULL;
	int i = 0;

	printf("ID: %i\n", ntohs(dns->header->id));	
	printf("Flags: %i, is response: %i\n", ntohs(dns->header->flags), DNS_QR(dns->header));
	printf("Query count: %i Answer count: %i Authoritative servers count: %i Additional records count: %i\n", ntohs(dns->header->query_count), ntohs(dns->header->answer_count), ntohs(dns->header->auth_servers_count), ntohs(dns->header->additional_records_count));
	node = dns->queries->head;
	printf("Queries:\n");
	while(node)
	{
		dns_query = (dns_query_t*)node->element;
		printf("\tName: ");
		print_std_dns_notation(dns_query->name);
		printf("\tType: %i Class: %i\n", ntohs(dns_query->type), ntohs(dns_query->class));
		node = node->next;
	}

	node = dns->answers->head;
	if(node)
		printf("Answers:\n");
	while(node)
        {    
                dns_resource_record = (dns_resource_record_t*)node->element;
                printf("\tName: ");
                print_std_dns_notation(dns_resource_record->name);
                printf("\tType: %i Class: %i TTL: %i Data Length: %i\n\tData:", ntohs(dns_resource_record->type), ntohs(dns_resource_record->class), ntohl(dns_resource_record->TTL), ntohs(dns_resource_record->data_length));
		for (i = 0; i < ntohs(dns_resource_record->data_length); i++)
			printf("%x",*(dns_resource_record->data + i));
		printf("\n");
                node = node->next;
        }

	node = dns->auth_servers->head;
	if(node)
		printf("Authoritative Servers:\n");
	while(node)
        {    
                dns_resource_record = (dns_resource_record_t*)node->element;
                printf("\tName: ");
                print_std_dns_notation(dns_resource_record->name);
                printf("\tType: %i Class: %i TTL: %i Data Length: %i\n\tData:", ntohs(dns_resource_record->type), ntohs(dns_resource_record->class), ntohl(dns_resource_record->TTL), ntohs(dns_resource_record->data_length));
		for (i = 0; i < ntohs(dns_resource_record->data_length); i++)
			printf("%x",*(dns_resource_record->data + i));
		printf("\n");
                node = node->next;
        }

	node = dns->additional_records->head;
	if(node)
		printf("Additional Records:\n");
	while(node)
        {    
                dns_resource_record = (dns_resource_record_t*)node->element;
                printf("\tName: ");
                print_std_dns_notation(dns_resource_record->name);
                printf("\tType: %i Class: %i TTL: %i Data Length: %i\n\tData:", ntohs(dns_resource_record->type), ntohs(dns_resource_record->class), ntohl(dns_resource_record->TTL), ntohs(dns_resource_record->data_length));
		for (i = 0; i < ntohs(dns_resource_record->data_length); i++)
			printf("%x",*(dns_resource_record->data + i));
		printf("\n");
                node = node->next;
        }
	printf("\n");

}

/*
 * release_runmon_packet: frees runmon packet resources if no longer needed.
 */
void release_runmon_packet(runmon_packet* packet)
{
	linked_list_node *node = packet->dependencies->head;
	linked_list_node *aux = NULL;
	runmon_packet *dependency = NULL;
	//free(packet->ethernet);
	//free(packet->ip);
	//free(packet->transport);
	free(packet->time);

        switch(packet->protocol_type)
        {   
                case SIP:
			if(packet->protocol_type)
                        	release_sip((sip_packet*)packet->protocol);
                        break;
                case DNS:
                        release_dns((dns_packet*)packet->protocol);
                        break;
                default:
                        //LOG THIS!
                break;
        }	
	
	//free(packet->PO); //CONSIDER THIS AFTER! not sure if you'll use the same string... why not?
	while (node)
	{
		dependency = (runmon_packet*)node->element;
		dependency->associations--;
		node = node->next;
	}
	delete_linked_list(packet->dependencies);
	
	free(packet->pkthdr);
	free(packet->data);
	
	free(packet);
}

/*
 * eval_selector_from_packet: return a value by selecting the package matching value
 */

void *eval_selector_from_packet(runmon_packet *packet, char *selector)
{
	char *label, *next_label = NULL;
//	label = strtok(selector, &next_label);
//	if(strcasecmp("ethernet", label) == 0)
//	{
//}
}

typedef unsigned char leafnode;

#define VARIBLES_AMMOUNT_TO_BE_SAVED 3 //this will depend on properties 
linked_list *saved_messages;
linked_list *saved_messages_locks;
unsigned long long *pass_verdicts, *fail_verdicts;
char *current_status;

#define LN_REQ_F_ADS 0
#define LN_RES_F_ADS 1
#define LN_REQ_NF_ADS_EQQ 2
#define LN_RES_NF_ADS_EQA 3

#define ADS_PO "ADS"

/*
 * equal_queries: auxiliary function to compare two DNS packets queries.
 */
BOOL equal_queries(dns_packet *packet1, dns_packet *packet2)
{
	linked_list_node *node1 = NULL, *node2 = NULL;
	dns_query_t *query1 = NULL, *query2 = NULL;
	if (packet1->header->query_count == packet2->header->query_count)
	{
		node1 = packet1->queries->head;
		node2 = packet2->queries->head;
		while(node1 && node2)
		{
			query1 = (dns_query_t*)node1->element;
			query2 = (dns_query_t*)node2->element;
			if(query1->class != query2->class || query1->type != query2->type || strcasecmp(query1->name, query2->name) != 0)
				return FALSE;
			node1 = node1->next;
                	node2 = node2->next;
		}
	}
	return TRUE;
}

/*
 * equal_answers: auxiliary function to compare two DNS packets answers. some code can be reused and use to compare compleletly RRs, ATM IDK
 */
BOOL equal_answers(dns_packet *packet1, dns_packet *packet2)
{
	linked_list_node *node1 = NULL, *node2 = NULL;
	dns_resource_record_t *answer1 = NULL, *answer2 = NULL;
	if (packet1->header->answer_count == packet2->header->answer_count)
	{
		node1 = packet1->answers->head;
		node2 = packet2->answers->head;
		while(node1 && node2)
		{
			answer1 = (dns_resource_record_t*)node1->element;
			answer2 = (dns_resource_record_t*)node2->element;
			//no TTL since they can change
			if(answer1->class != answer2->class || answer1->type != answer2->type || strcasecmp(answer1->name, answer2->name) != 0 || answer1->data_length != answer2->data_length || *((int*)answer1->data) !=  *((int*)answer2->data)) //for the time being I'm just comparing A records...
				return FALSE;
			node1 = node1->next;
                	node2 = node2->next;
		}
	}
	return TRUE;
}

/*
 * match_ports_and_IPs: auxiliary function that helps determine if source port is and dest port matches responses of two packets
 */
BOOL match_ports_and_IPs(runmon_packet *runmon1, runmon_packet *runmon2)
{
	u_short p1sp, p1dp, p2sp, p2dp;
	in_addr_t p1si, p1di, p2si, p2di;

	//if(runmon1->transport_type != runmon2->transport_type)
	//	return FALSE; //I'm uncertain if this is actually possible... leave without a check ATM

	p1sp = (runmon1->transport_type == UDP)?((udph*)runmon1->transport)->uh_sport:((tcph*)runmon1->transport)->th_sport;
	p1dp = (runmon1->transport_type == UDP)?((udph*)runmon1->transport)->uh_dport:((tcph*)runmon1->transport)->th_dport;

	p2sp = (runmon2->transport_type == UDP)?((udph*)runmon2->transport)->uh_sport:((tcph*)runmon2->transport)->th_sport;
	p2dp = (runmon2->transport_type == UDP)?((udph*)runmon2->transport)->uh_dport:((tcph*)runmon2->transport)->th_dport;

	p1si = runmon1->ip->ip_src.s_addr;
	p1di = runmon1->ip->ip_dst.s_addr;
	
	p2si = runmon2->ip->ip_src.s_addr;
	p2di = runmon2->ip->ip_dst.s_addr;

	if (p1sp != p2dp || p1dp != p2sp || p1si != p2di || p1di != p2si)
		return FALSE;

	return TRUE;

}

/*
 * get_property_of_variable: function to get the property associated with a variable
 */
int get_property_of_variable(int variable_index)//this will probably change for a struct var prototype or something like that
{
	return 1;
}

/*
 * match_packet_against_leafnode: function to 
 */
void match_packet_against_leafnode(leafnode ln, runmon_packet *packet)
{
	dns_packet *dns = (dns_packet*)packet->protocol;
	int index_of_var = 0;
	pthread_mutex_t *lock = NULL;
	linked_list *packet_list = NULL;
	int index_of_x1 = 0, index_of_y1 = 1, index_of_a1 = 2;
	linked_list_node *node = NULL;
	runmon_packet *stored_packet = NULL, *auxiliary_packet = NULL, *auxiliary_packet2 = NULL;
	dns_packet *stored_dns = NULL;
	int i = 0;
	
	switch(ln)
	{
		
		case LN_REQ_F_ADS: //check if it is a DNS reqeust from the ADS PO and save it in the LL
			index_of_var = 0;
			if(DNS_QR(dns->header) == 0 && strcasecmp(packet->PO,ADS_PO) == 0) //request from ADS
			{
                                lock = (pthread_mutex_t*)linked_list_get_nth(saved_messages_locks, index_of_var);
                                pthread_mutex_lock(lock);
                                packet_list = (linked_list*)linked_list_get_nth(saved_messages, index_of_var);
                                packet->reference_count++;
                                linked_list_add(packet_list, packet);
                                pthread_mutex_unlock(lock);
			}
		break;
		case LN_RES_F_ADS: //check if it's a DNS response from ADS, save it in the LL and add assocs
			index_of_var = 1;
			if(DNS_QR(dns->header) == 1 && strcasecmp(packet->PO,ADS_PO) == 0) //reply from ADS
			{
				lock = (pthread_mutex_t*)linked_list_get_nth(saved_messages_locks, index_of_x1);
				pthread_mutex_lock(lock);
				packet_list = (linked_list*)linked_list_get_nth(saved_messages, index_of_x1);
				node = packet_list->head;
				///go through all list and match a request, if so, add assoc to the package, unlock, lock the other list, add unluck and goodbye 
				while(node)
				{
					stored_packet = (runmon_packet*)node->element;
					stored_dns = (dns_packet*)stored_packet->protocol;
					
					if(dns->header->id == stored_dns->header->id && equal_queries(dns, stored_dns) && match_ports_and_IPs(packet, stored_packet) && timeval_isgreaterthan(packet->time, stored_packet->time)) //is response of x
					{
						stored_packet->associations++;
						pthread_mutex_unlock(lock);
				
						lock = (pthread_mutex_t*)linked_list_get_nth(saved_messages_locks, index_of_var);
                                		pthread_mutex_lock(lock);
						packet_list = (linked_list*)linked_list_get_nth(saved_messages, index_of_var);
						packet->reference_count++;
						linked_list_add(packet->dependencies, stored_packet);
						linked_list_add(packet_list, packet);
						pthread_mutex_unlock(lock);
	//CONSIDER DROPPING the packages with old TTL and get this new? or which equeal request response to conserve? 
						return;
					}
					node = node->next;
				}
                                pthread_mutex_unlock(lock);
			}
		break;
		case LN_REQ_NF_ADS_EQQ: //check if it is a DNS request not from the ADS PO and save it in the LL if there is a response that already have the same queries.
			index_of_var = 2;
			if(DNS_QR(dns->header) == 0 && strcasecmp(packet->PO,ADS_PO) != 0)
			{
				lock = (pthread_mutex_t*)linked_list_get_nth(saved_messages_locks, index_of_y1);		
				pthread_mutex_lock(lock);packet_list = (linked_list*)linked_list_get_nth(saved_messages, index_of_y1);
				node = packet_list->head;
				while(node)
                                {
                                        stored_packet = (runmon_packet*)node->element;
                                        stored_dns = (dns_packet*)stored_packet->protocol;
					
					if(equal_queries(dns, stored_dns) && timeval_isgreaterthan(packet->time, stored_packet->time))
					{
						stored_packet->associations++;
                                                pthread_mutex_unlock(lock);
						
						lock = (pthread_mutex_t*)linked_list_get_nth(saved_messages_locks, index_of_var);
                                                pthread_mutex_lock(lock);
                                                packet_list = (linked_list*)linked_list_get_nth(saved_messages, index_of_var);
                                                packet->reference_count++;
                                                linked_list_add(packet->dependencies, stored_packet);
                                                linked_list_add(packet_list, packet);
                                                pthread_mutex_unlock(lock);
                                                return;
					}
					
				 	node = node->next;
				}	
				pthread_mutex_unlock(lock);
			}
		break;
		case LN_RES_NF_ADS_EQA:
			index_of_var = 3;
			if(DNS_QR(dns->header) == 1 && strcasecmp(packet->PO,ADS_PO) != 0)
			{
				lock = (pthread_mutex_t*)linked_list_get_nth(saved_messages_locks, index_of_a1);
                                pthread_mutex_lock(lock);
				packet_list = (linked_list*)linked_list_get_nth(saved_messages, index_of_a1);
				node = packet_list->head;
                                while(node)
                                {
                                        stored_packet = (runmon_packet*)node->element;
                                        stored_dns = (dns_packet*)stored_packet->protocol;
					if(dns->header->id == stored_dns->header->id && equal_queries(dns, stored_dns) && match_ports_and_IPs(packet, stored_packet) && timeval_isgreaterthan(packet->time, stored_packet->time)) //is response of a
					{
						//compare y packet responses, get y, compare the answers report a veredict.
						auxiliary_packet = (runmon_packet*)linked_list_get(stored_packet->dependencies); //this is y
						auxiliary_packet2 = (runmon_packet*)linked_list_get(auxiliary_packet->dependencies);
						//we conclude something here about some property, no need for re-report in case of emptying packages
						auxiliary_packet2->completed_properties[get_property_of_variable(index_of_var)] = TRUE;
						auxiliary_packet->completed_properties[get_property_of_variable(index_of_var)] = TRUE;
						stored_packet->completed_properties[get_property_of_variable(index_of_var)] = TRUE;
						packet->completed_properties[get_property_of_variable(index_of_var)] = TRUE;
						//report here and then delete necesary a packets
						if(equal_answers((dns_packet*)auxiliary_packet->protocol, dns))
						{
							if(DEBUG)
								printf("--Pass verdict--\n\tMessages(in trace): %i, %i, %i, %i complete property %i.\n\n", auxiliary_packet2->location_in_trace, auxiliary_packet->location_in_trace, stored_packet->location_in_trace, packet->location_in_trace, 1);
							pass_verdicts[0]++;
							current_status[0] = CURRENT_STATUS_PASS;
						}
						else
						{
							if(DEBUG)
                                                                printf("--Fail verdict--\n\tMessages(in trace): %i, %i, %i, %i fail property: %i.\n\n", auxiliary_packet2->location_in_trace, auxiliary_packet->location_in_trace, stored_packet->location_in_trace, packet->location_in_trace, 1);	
							fail_verdicts[0]++;
							current_status[0] = CURRENT_STATUS_FAIL;
						}
						if(--stored_packet->reference_count == 0 && stored_packet->associations == 0)//no need for this packet release
                                                        release_runmon_packet((runmon_packet*)linked_list_delete_nth(packet_list, i));
						else
                                                        linked_list_delete_nth(packet_list, i);//not remove the packet itself, but, just from the LL
						pthread_mutex_unlock(lock);
						return;
					}
					node = node->next;
					i++;
				}
				pthread_mutex_unlock(lock);
			}
		break;
		default:
			return;
			//No default
	}
}

struct timeval *last_observed_time; //last observed time                                                               |        {
pthread_mutex_t *last_observed_time_lock; //to guarantee thread safe of time reading and writing. 

void process_packet(int property_count, struct pcap_pkthdr *pkthdr, u_char *packet)
{
	static count = 0;
	static struct timeval *offset;
	struct timeval *result, *time; 
	ethernet_h *ether = NULL;
	ip4 *ip = NULL;
	char ip_source[INET_ADDRSTRLEN], ip_dest[INET_ADDRSTRLEN];
	u_char *payload;
	tcph *tcp = NULL;
	udph *udp = NULL;
	void *protocol = NULL;
	runmon_packet *message = (runmon_packet*)malloc(sizeof(runmon_packet));
	transport_e packet_transport;
	protocol_e packet_protocol;
	int i =0; //DELETE probably since it will be for each leaf not each static leaf
	BOOL packet_kept = FALSE;
	BOOL *completed_properties = (BOOL*)malloc(property_count * sizeof(BOOL));
	u_short source_port = 0, destination_port = 0;
	
	if(count == 0)
	{
		offset = (struct timeval*)malloc(sizeof(struct timeval));
		offset->tv_sec = pkthdr->ts.tv_sec;
		offset->tv_usec = pkthdr->ts.tv_usec;
	}
	
	result = (struct timeval*)malloc(sizeof(struct timeval));
	time = (struct timeval*)&pkthdr->ts;
		
	timeval_substract(result,time,offset);

	pthread_mutex_lock(last_observed_time_lock);
	last_observed_time->tv_sec = result->tv_sec;
	last_observed_time->tv_usec = result->tv_usec;
	pthread_mutex_unlock(last_observed_time_lock);

	if (pkthdr->caplen < ETHERNET_HEADER_SIZE)
	{
		//LOG this!
		return;
	}

	ether = (ethernet_h*)packet;
	if (ether->ether_type != ETHERNET_IPv4_TYPE)
	{
		//LOG this!
		return;
	}
	
	ip = (ip4*)(packet + ETHERNET_HEADER_SIZE);
		
	//Leaving this here for future PO cathegorization... 
	inet_ntop(AF_INET, &ip->ip_src, ip_source, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip->ip_dst, ip_dest, INET_ADDRSTRLEN);
	
	if (ip->ip_p == IP_PROTO_UDP)
	{
		udp = (udph*)(packet + ETHERNET_HEADER_SIZE + (IP_HL(ip) * 4)); //* 4 because size expressed in 32bit 
		payload = (u_char*)(packet + ETHERNET_HEADER_SIZE + (IP_HL(ip) * 4) + UDP_HEADER_SIZE); //* 4 because size expressed in 32bit  
		packet_transport = UDP;
	}	 
	else if (ip->ip_p == IP_PROTO_TCP)
	{
		tcp = (tcph*)(packet + ETHERNET_HEADER_SIZE + (IP_HL(ip) * 4)); //* 4 because size expressed in 32bit 
		payload = (u_char*)(packet + ETHERNET_HEADER_SIZE + (IP_HL(ip) * 4) + (TH_OFF(tcp) * 4)); //* 4 because size expressed in 32bit 
		packet_transport = TCP;
	}
	else
	{
		//LOG this!
		return;
	}

	//printf("%d) length=%d time=%d.%d. from:%s:%d to:%s:%d transport:%s \n", ++count, pkthdr->len, result->tv_sec, result->tv_usec, ip_source, ntohs((udp)?udp->uh_sport:tcp->th_sport), ip_dest, ntohs((udp)?udp->uh_dport:tcp->th_dport), (udp)?"UDP":"TCP"); //interested in all packages?
	source_port = ntohs((udp)?udp->uh_sport:tcp->th_sport);
        destination_port = ntohs((udp)?udp->uh_dport:tcp->th_dport);
	
	//WHERE TO SEND THIS? I mean choose depending on ports and so on...
        if(source_port == SIP_PORT || destination_port == SIP_PORT)
        {
                packet_protocol = SIP;
                protocol = process_sip(payload, pkthdr->len - (payload - packet));
        }
        else if(source_port == DNS_PORT || destination_port == DNS_PORT)
	{
		packet_protocol = DNS;
		protocol = process_dns(payload, pkthdr->len - (payload - packet));
	}
	else
	{
		//LOG THIS!
	}
	
	if(strcmp(ip_source, "62.73.5.128") == 0 || strcmp(ip_dest, "62.73.5.128") == 0 || strcmp(ip_source, "62.73.5.21") == 0 || strcmp(ip_dest, "62.73.5.21") == 0)
		message->PO = "ADS";
	else
		message->PO = "other";


	memset(completed_properties, 0, sizeof(BOOL) * property_count);
	
	//add all message parts
	message->ethernet = ether;	
	message->ip = ip;
	message->time = result;
	message->transport_type = packet_transport;
	message->protocol_type = packet_protocol;
	message->location_in_trace = ++count;
	message->reference_count = 0;
	message->associations = 0;
	message->protocol = protocol;
	message->dependencies = create_linked_list();
	message->completed_properties = completed_properties;
	message->pkthdr = pkthdr;
	message->data = packet;
		
	switch(packet_transport)
	{
		case UDP:	
			message->transport = udp;
			break;
		default:
			message->transport = tcp;
	}

	if(message->protocol == NULL)
	{
		release_runmon_packet(message);
		if(DEBUG)
			printf("--CORRUPT PACKET--\n\tMessage(in trace): %i\n\n", count);
		return;
	}

	if(message->protocol_type == DNS)
	{
		//print_dns((dns_packet*)message->protocol);
		for (i = 0; i < 4; i++)
			match_packet_against_leafnode(i, message);
		if(message->reference_count == 0)
                	release_runmon_packet(message);//not interested in this packet
		return;
	}

/*	for (i = 0; i < 2 * VARIBLES_AMMOUNT_TO_BE_SAVED; i++)
		packet_kept |= match_packet_vs_leafnode(i, message);
	if(message->reference_count == 0)
		release_runmon_packet(message);//not interested in this packet
*/
}

void *serve_conn(void *serve_conn_ptr)//make sure this is threadable, should be from the point of view that we are serving different BIOs, but, underlying data structures should be considered
{
	//2implement... for now echo server
		
	u_char *message;
	serve_conn_t *sct = (serve_conn_t*)serve_conn_ptr;
	int buffersize = sct->buffersize;
	BIO *bio = sct->bio;
	void *buffer = malloc(buffersize);
	void *temp_buffer = NULL;
	void *buffer_ptr = buffer;
	int buff_size = buffersize;
	int available, consumed;
	stream_state_e state = INIT;
	u_char aux_byte;
	struct pcap_pkthdr *header = NULL;
	u_char *packet;
	
	ssize_t operation_length = 0;
	
	do
	{
		operation_length = read_from_stream(bio, buffer_ptr, buffersize);
		
		if(operation_length > 0)
		{
			//from here ***
			available = (buffer_ptr - buffer) + operation_length;
			consumed = 0;

			if (state == INIT) //we need one and we know it's bigger than 0... so, no need to specify
			{
				aux_byte = *((u_char*)buffer);
				state = A_TV_SEC_L;
				consumed = 1;
				available -= consumed;
				header = malloc(1 * sizeof(struct pcap_pkthdr));
			}
			//not else if because after one state more data can be available and we can process it... 
			if(state == A_TV_SEC_L && available >= aux_byte)//means we have enough to pick the tv_sec and we are after tv_sec length
			{
				if(aux_byte == sizeof(int32_t))
					header->ts.tv_sec = ntohl(*((uint32_t*)(buffer + consumed)));
				else // the only other chance 64 bit...
					header->ts.tv_sec = ntohll(*((uint64_t*)(buffer + consumed)));
				state = A_TV_SEC;
				consumed += aux_byte;
				available -= consumed;
			}
			
			if(state == A_TV_SEC && available >= 1)//we need to read just the next number
			{
				aux_byte = *((u_char*)(buffer + consumed));
				state = A_TV_USEC_L;
				consumed += 1;
				available -= consumed;
			}

                        if(state == A_TV_USEC_L && available >= aux_byte)//means we have enough to pick the tv_usec and we are after tv_sec length
                        {
                                if(aux_byte == sizeof(int32_t))
                                        header->ts.tv_usec = ntohl(*((uint32_t*)(buffer + consumed)));
                                else // the only other chance 64 bit...
                                        header->ts.tv_usec = ntohll(*((uint64_t*)(buffer + consumed)));
                                state = A_TV_USEC;
                                consumed += aux_byte;
                                available -= consumed;
                        }

			if (state == A_TV_USEC && available >= sizeof(int32_t))
			{
				header->caplen = ntohl(*((uint32_t*)(buffer + consumed)));
				state = A_CAPLEN;
				consumed += sizeof(int32_t);
				available -= consumed;
			}

			if (state == A_CAPLEN && available >= sizeof(int32_t))
			{
				header->len = ntohl(*((uint32_t*)(buffer + consumed)));
				state = A_LEN;
				consumed += sizeof(int32_t);
				available -= consumed;
			}

			if (state == A_LEN && available >= header->caplen)// we can grab the rest of the packet bro
			{
				packet = malloc(header->caplen * sizeof(u_char));
				memcpy(packet, buffer + consumed, header->caplen);
				state = INIT; 
				consumed += header->caplen;
				process_packet(sct->properties_count, header, packet);
			}
			/*
 			//echo server
			for (i = 0, consumed = 0;  i < (buffer_ptr - buffer) + operation_length; i++)
			{
				if(*(char*)(buffer + i) == '\n')
				{
					//write_to_stream(bio, buffer + consumed, i - consumed + 1);
					printf("\n");
					consumed = i + 1;
				}
				else
					printf("%x ",*((unsigned char*)(buffer + i)));
			}*/
			//to here consumed is necesary and proper operation of each program, maybe in the future we should include a func call and pass as an argument that function or something and add the consumed length
			buff_size = buffersize + (buffer_ptr - buffer) + operation_length - consumed;
			temp_buffer = malloc(buff_size);
			memcpy(temp_buffer, buffer + consumed, buff_size - buffersize);
			free(buffer);
			buffer = temp_buffer;
			buffer_ptr = buffer + (buff_size - buffersize);
		}
		else if(operation_length < 0)
			exit(EXIT_FAILURE);
		
	}
	while (operation_length != 0);
	
        BIO_free_all(bio);	
}

BOOL still_running; //variable used to indicate if the monitoring is still in progress.
BOOL *keep_old_messages; //variable to specify special conditions of messages kept unless replaced by new ones

/*
 * compare_DNS_answers: function that determines if DNS answers are the same
 */
BOOL compare_DNS_answers(runmon_packet *p1, runmon_packet *p2)
{
	dns_packet *dns1 = NULL, *dns2 = NULL;
	if(p1->protocol_type != DNS || p2->protocol_type != DNS)
		return FALSE;
	dns1 = (dns_packet*)p1->protocol;
	dns2 = (dns_packet*)p2->protocol;
	return (equal_queries(dns1,dns2) && equal_answers(dns1, dns2));
}

/*
 * empty_equal_kept_messages: auxiliary function to delete duplicated un-associated messages non thread-safe
 */
void empty_equal_kept_messages (linked_list *ll, BOOL (*comp_func)(runmon_packet*, runmon_packet*))
{
	linked_list_node *node = ll->head, *aux = NULL;
	runmon_packet *packet = NULL, *compare = NULL;
	int i = 0, j = 0;

	while (node)
	{
		aux = node->next;
		packet = (runmon_packet*)node->element;
		j = i + 1;
		node = node->next;
		while(aux)
		{
			compare = (runmon_packet*)aux->element;
			aux = aux->next;
			if(comp_func(packet, compare))
			{
				if(timeval_isgreaterthan(packet->time, compare->time))
				{
					if(!compare->associations)//all necesary to delete this packet 
					{
						if(--compare->reference_count == 0)
							release_runmon_packet((runmon_packet*)linked_list_delete_nth(ll, j));
						else 	
							linked_list_delete_nth(ll, j);
						j--;
					}	
				}
				else if(timeval_isgreaterthan(compare->time, packet->time))
				{
					if(!packet->associations)
					{
						if(--packet->reference_count == 0)
							release_runmon_packet((runmon_packet*)linked_list_delete_nth(ll, i));
                                                else
                                                        linked_list_delete_nth(ll, i);
						i--;
						break;
					}
				}
			}
			j++;
		}
		i++;
	}
}

/*
 * empty_old_messages: function that purges the message lists, the timeout variable is used to purge messages that are older than that time in usecs
 */
void empty_old_messages(unsigned long timeout_usec)
{
	linked_list_node *node = saved_messages->head;
	linked_list_node *lock_node = saved_messages_locks->head;
	linked_list_node *packet_node = NULL;
	linked_list *packet_list = NULL;
	pthread_mutex_t *lock = NULL;
	runmon_packet *packet = NULL;
	int i = 0, j = 0;
	unsigned long last_packet_time = 0;

        pthread_mutex_lock(last_observed_time_lock);
        last_packet_time = last_observed_time->tv_sec * 1000000 + last_observed_time->tv_usec;
        pthread_mutex_unlock(last_observed_time_lock);

	while(node)
	{
		lock = (pthread_mutex_t*)lock_node->element;
		pthread_mutex_lock(lock);
		packet_list = (linked_list*)node->element;
		packet_node = packet_list->head;	
		j = -1;
		
		if(keep_old_messages[i])
		{
			empty_equal_kept_messages(packet_list, compare_DNS_answers);
			packet_node = NULL;
		}

		while(packet_node)
		{
			j++;
			packet = (runmon_packet*)packet_node->element;
			packet_node = packet_node->next;

			if(packet->associations && timeout_usec && (packet->time->tv_sec * 1000000 + packet->time->tv_usec + timeout_usec >= last_packet_time)) // if timeout is 0 means delete all anyway
				continue; // this means if packet is still meant to be in the queues
	
			if(!packet->completed_properties[get_property_of_variable(i)] && timeout_usec > 0) 
			{
				if(DEBUG)
					printf("--FAIL verdict--\n\tMessage(in trace): %i, incomplete in property %i.\n\n", packet->location_in_trace, i + 1);
                        	fail_verdicts[get_property_of_variable(i)]++;
				current_status[get_property_of_variable(i)] = CURRENT_STATUS_FAIL;
			}
			else if(!packet->completed_properties[get_property_of_variable(i)] && timeout_usec == 0)
			{
				if(DEBUG)
					printf("--Inconclusive verdict--\n\tMessage(in trace): %i, incomplete in property %i.\n\n", packet->location_in_trace, i + 1);
				//report inconclusive??
			}
                        if(--packet->reference_count == 0)//no need for this packet release
                                release_runmon_packet(packet);
                       	linked_list_delete_nth(packet_list, j);
			j--; //still transversing the ll, so, we need to set the new pointer location back since last packet was deleted
		}
		
		pthread_mutex_unlock(lock);
		node = node->next;
		lock_node = lock_node->next;
		i++;
	}
}

/*
 * fail_timeout_func function for the fail timeout thread, takes as the parameter the time 
 */

void *fail_timeout_func(void *param)
{
	unsigned long timeout = *((unsigned long*)param);
	while(TRUE)
	{
		usleep(timeout);
		if(still_running)
			empty_old_messages(timeout);	
		else
			break;
	}
	return NULL;
}

/*
 * print_status: function to display the current status to stdout
 */

void print_status(int property_count)
{
	//static int chars_to_delete = 0;
	int i;
	static const char *header = "Status:\n";
	static const char *property = "\tProperty %i:\n\t\tCurrent Status:%s\n\t\tPass verdicts:%i\n\t\tFail Verdicts:%i\n";
	static const char *pass_str = "PASS";
	static const char *fail_str = "FAIL";
	static const char *inconclusive_str = "INCONCLUSIVE";
	char *curr_status = NULL;

	system("clear");
	printf(header);
	
	for (i = 0; i < property_count; i++)
	{
		switch(current_status[i])
		{
			case CURRENT_STATUS_FAIL: 
				curr_status = (char*)fail_str;
				break;
			case CURRENT_STATUS_PASS:
				curr_status = (char*)pass_str;
				 break;
			default:
                                curr_status = (char*)inconclusive_str;
		}
		printf(property, i + 1, curr_status, pass_verdicts[i], fail_verdicts[i]);
	}	
}

/*
 * report_status: function for a thread to report status periodically
 */
void *report_status(void *param)
{
	report_status_t *rst = (report_status_t*)param;
	
	 
	while(TRUE)
	{
		usleep(rst->period);
		if(still_running)
			print_status(rst->properties_count);
		else
			break;
	}
	return NULL;
}

#define FAIL_TIMEOUT_TIME 16*1000000
#define REPORT_STATUS_PERIOD 2000000

int main(char **argv, int argc)
{
	//all this params should be read from a conf file...
	char *certificate_file = "./server.crt";
	char *private_key_file = "./server.key";
	int buffersize = 4096;
	char *ip_address_string = "0.0.0.0"; //2change from host to host
	char *port_string = "26965"; //TSP base 30
	
	//pcap filter as well
	//...............
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	BIO *bio = NULL;
	int client = 0;
	struct in_addr *IP_addrr = (struct in_addr*)malloc(1 * sizeof(struct in_addr));
	int port = atoi(port_string);
	int listener;
	struct sockaddr_in *addr;
	int *len;
	debug = DEBUG;
	pthread_t *service_thread = NULL;
	pthread_t timeout_checker_thread, report_status_thread;
	pthread_mutex_t *lock;
	serve_conn_t *sct = NULL;
	int thread_status;
	int properties_count = 1, i;
	report_status_t *rst = malloc(1 * sizeof(report_status_t));
        int stored_variables_count = VARIBLES_AMMOUNT_TO_BE_SAVED;
	unsigned long fail_timeout_time = FAIL_TIMEOUT_TIME;
	linked_list *packet_list = NULL;


	len = malloc(1 * sizeof(int));
	*len = sizeof(struct sockaddr_in);
	inet_aton(ip_address_string, IP_addrr); //check if DNS if possible here? 
	init_ssl();
	listener = open_listener(IP_addrr, port);

	if (listener < 0)
		exit(1);
	
	ctx = setup_SSL_CTX(certificate_file, private_key_file);

	if (!ctx)
		exit(1);
	
	last_observed_time = malloc(1 * sizeof(struct timeval));
	last_observed_time->tv_sec = 0;
        last_observed_time->tv_usec = 0;
        last_observed_time_lock = (pthread_mutex_t*)malloc(1 * sizeof(pthread_mutex_t));
        pthread_mutex_init(last_observed_time_lock, NULL);
	
	rst->period = REPORT_STATUS_PERIOD;
        rst->properties_count = properties_count;

	saved_messages = create_linked_list();
        saved_messages_locks = create_linked_list();
        keep_old_messages = (BOOL*)malloc(stored_variables_count * sizeof(BOOL));

        for (i = 0; i < stored_variables_count; i++)
        {
                packet_list = create_linked_list();
                linked_list_add(saved_messages, packet_list);

                lock = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t) * 1);
                pthread_mutex_init(lock, NULL);
                linked_list_add(saved_messages_locks, lock);

                keep_old_messages[i] = 0;
        }
	//this should be a function call depending on the var to keep or not the messages
	keep_old_messages[1] = 1;

	pass_verdicts = (unsigned long long*)malloc(sizeof(unsigned long long) * properties_count);
	memset(pass_verdicts, 0, sizeof(unsigned long long) * properties_count);
	fail_verdicts = (unsigned long long*)malloc(sizeof(unsigned long long) * properties_count);
	memset(fail_verdicts, 0, sizeof(unsigned long long) * properties_count);
	
	current_status = (char*)malloc(sizeof(char) * properties_count);
        for (i = 0; i < properties_count; i++)
                current_status[i] = CURRENT_STATUS_INCONCLUSIVE;

	pthread_create(&timeout_checker_thread, NULL, &fail_timeout_func, &fail_timeout_time);
        pthread_create(&report_status_thread, NULL, &report_status, rst);
        pthread_detach(timeout_checker_thread);
        pthread_detach(report_status_thread);

	still_running = TRUE;

	while (TRUE)
	{
		addr = (struct sockaddr_in*)malloc(1 * *len);
		client = accept (listener, (struct sockaddr*)addr, len);
		
		//perhaps to check here if the connection is authorized?
		
		bio = BIO_new_ssl(ctx, FALSE);
		if(!bio)
       	 	{   
               		report_error("Unable to allocate BIO pointer.\n", NULL);
                	continue;
        	}   

        	BIO_get_ssl(bio, &ssl);
        	if (!ssl) 
        	{   
                	report_error("Unable to allocate SSL pointer.\n", NULL);
                	BIO_free_all(bio);
                	continue;
        	}
		
		SSL_set_fd(ssl, client);
		SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
		sct = (serve_conn_t*)malloc(1 * sizeof(serve_conn_t));
		sct->bio = bio;
		sct->buffersize = buffersize;
		sct->properties_count = properties_count;
		service_thread = (pthread_t*)malloc(1 * sizeof(pthread_t));

		thread_status = pthread_create(service_thread, NULL, serve_conn, sct);
		
		if (thread_status)
		{
			report_error("Couldn't create service thread", NULL);
			free(sct);
			BIO_free_all(bio);
			continue;
		}

		thread_status = pthread_detach(*service_thread);
	
		if (thread_status)
		{
			report_error("Couldn't detach thread", NULL);
			free(service_thread);
			free(sct);
			BIO_free_all(bio);
		}

	}
	
	free(last_observed_time);
	free(len);	
	free(IP_addrr);

	//free stuff here...
}
