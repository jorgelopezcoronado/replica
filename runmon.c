#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>	
#include <unistd.h>

#include "helpers.h"
#include "runmon.h"
#include "term.h"

#define DEBUG 1

#define CRLF "\r"

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

long TIME_CONSTRAINT;

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

#define LN_REQ_INV_P1 0
#define LN_RES_NPR_P1 1
#define LN_REQ_INV_P2 2
#define LN_RES_SUC_P2 3
#define LN_REQ_NAK_P3 4
#define LN_RES_NPWT_P3 5

/*
 * match_packet_vs_leafnode: function to compare a leaf node atoms against a packet
 */
BOOL match_packet_vs_leafnode(leafnode ln, runmon_packet *packet)
{
	sip_packet *sip = (sip_packet*)packet->protocol;
	int index_of_var = 0, i; //determined by assignation of properties
	linked_list_node *node = NULL, *packet_node = NULL;
	linked_list *packet_list = NULL;	
	runmon_packet *stored_packet = NULL; 
	sip_packet *stored = NULL; 
	char *cseq = NULL, *stored_cseq = NULL;
	void *header_field_value = NULL;
	header_field *headerfield = NULL;
	pthread_mutex_t *lock = NULL;

	switch(ln)
	{
		case LN_REQ_INV_P1:
			index_of_var = 0;
			if(sip->start_line->method != NULL && strcasecmp(sip->start_line->method, "INVITE") == 0) //Invite request property 1
			{	
				lock = (pthread_mutex_t*)linked_list_get_nth(saved_messages_locks, index_of_var);
                                pthread_mutex_lock(lock);
				packet_list = (linked_list*)linked_list_get_nth(saved_messages, index_of_var);
				packet->reference_count++;
				linked_list_add(packet_list, packet);
                                pthread_mutex_unlock(lock);
			}
			return TRUE;
		case LN_RES_NPR_P1:
			index_of_var = 0;
			if(sip->start_line->method == NULL && sip->start_line->status_code > 199 ) //non-provisional response
			{
				lock = (pthread_mutex_t*)linked_list_get_nth(saved_messages_locks, index_of_var);
				pthread_mutex_lock(lock);
				//now search if for the mathing request
				packet_list = (linked_list*)linked_list_get_nth(saved_messages, index_of_var);
				i = 0;
				node = packet_list->head;
				while(node)
				{
					stored_packet = (runmon_packet*)node->element;
					stored = (sip_packet*)stored_packet->protocol;
					cseq = NULL, stored_cseq = NULL;
					header_field_value = NULL;

					if(linked_list_transverse(sip->header_fields, &header_field_value))
						if(strcasecmp(((header_field*)header_field_value)->name, "CSeq") == 0)
                                                        cseq = ((header_field*)header_field_value)->value;
					while(!cseq && linked_list_transverse(NULL, &header_field_value))
						if(strcasecmp(((header_field*)header_field_value)->name, "CSeq") == 0)
                                                        cseq = ((header_field*)header_field_value)->value;

					packet_node = stored->header_fields->head;
					while (!stored_cseq && packet_node)
					{
						headerfield = (header_field*)packet_node->element;
						if(strcasecmp(headerfield->name, "CSeq") == 0)
							stored_cseq = headerfield->value;
						packet_node = packet_node->next;
					}
/*

					if(linked_list_transverse(stored->header_fields, &header_field_value))
					{
						printf("%s->%s\n", ((header_field*)header_field_value)->name, ((header_field*)header_field_value)->value);
						if(strcasecmp(((header_field*)header_field_value)->name, "CSeq") == 0)
                                                        stored_cseq = ((header_field*)header_field_value)->value;
					}
					while(!stored_cseq && linked_list_transverse(NULL, &header_field_value))
					{
						printf("%s->%s\n", ((header_field*)header_field_value)->name, ((header_field*)header_field_value)->value);
						if(strcasecmp(((header_field*)header_field_value)->name, "CSeq") == 0)
                                                        stored_cseq = ((header_field*)header_field_value)->value;
					}
	
*/
					if(strcasecmp(stored_cseq, cseq) == 0 && timeval_isgreaterthan(packet->time, stored_packet->time))//both sequence number matches its a response as well for stored sip
					{
						if(DEBUG)
							printf("--Pass verdict--\n\tMessages(in trace): %i, %i, completes property %i.\n\n", stored_packet->location_in_trace, packet->location_in_trace, index_of_var + 1);
						pass_verdicts[index_of_var]++;
						current_status[index_of_var] = CURRENT_STATUS_PASS;
						if(--stored_packet->reference_count == 0)//no need for this packet release
							release_runmon_packet((runmon_packet*)linked_list_delete_nth(packet_list, i));
						else
							linked_list_delete_nth(packet_list, i);//not remove the packet itself, but, just from the LL
						pthread_mutex_unlock(lock);
						return FALSE;
					}
					node = node->next;
					i++;
				}
				pthread_mutex_unlock(lock);
			}
			return FALSE;
		case LN_REQ_INV_P2:
			index_of_var = 1;
			if(sip->start_line->method != NULL && strcasecmp(sip->start_line->method, "INVITE") == 0) //Invite request property 2
                        {
				lock = (pthread_mutex_t*)linked_list_get_nth(saved_messages_locks, index_of_var);
                                pthread_mutex_lock(lock);
                                packet_list = (linked_list*)linked_list_get_nth(saved_messages, index_of_var);
                                packet->reference_count++;
                                linked_list_add(packet_list, packet);
                                pthread_mutex_unlock(lock);
			}
			return TRUE;
		case LN_RES_SUC_P2:
 			index_of_var = 1;
			if(sip->start_line->method == NULL && sip->start_line->status_code > 199 && sip->start_line->status_code < 300 ) //success response property 2 
			{
                                lock = (pthread_mutex_t*)linked_list_get_nth(saved_messages_locks, index_of_var);
                                pthread_mutex_lock(lock);
				//now search if for the mathing request
				packet_list = (linked_list*)linked_list_get_nth(saved_messages, index_of_var);
                                i = 0;
                                node = packet_list->head;
				
				while (node)
				{
                                        stored_packet = (runmon_packet*)node->element;
                                        stored = (sip_packet*)stored_packet->protocol;
					cseq = NULL;
					stored_cseq = NULL;
                                        header_field_value = NULL;

                                        if(linked_list_transverse(sip->header_fields, &header_field_value))
                                                if(strcasecmp(((header_field*)header_field_value)->name, "CSeq") == 0)
                                                        cseq = ((header_field*)header_field_value)->value;
                                        while(!cseq && linked_list_transverse(NULL, &header_field_value))
                                                if(strcasecmp(((header_field*)header_field_value)->name, "CSeq") == 0)
                                                        cseq = ((header_field*)header_field_value)->value;

                                        if(linked_list_transverse(stored->header_fields, &header_field_value))
                                                if(strcasecmp(((header_field*)header_field_value)->name, "CSeq") == 0)
                                                        stored_cseq = ((header_field*)header_field_value)->value;
                                        while(!stored_cseq && linked_list_transverse(NULL, &header_field_value))
                                                if(strcasecmp(((header_field*)header_field_value)->name, "CSeq") == 0)
                                                        stored_cseq = ((header_field*)header_field_value)->value;

					if(strcasecmp(stored_cseq, cseq) == 0 && timeval_isgreaterthan(packet->time, stored_packet->time))//both sequence number matches its a response as well for stored sip and packet y>x
					{
						if(DEBUG)
							printf("--Pass verdict--\n\tMessages(in trace): %i, %i, completes property %i.\n\n", stored_packet->location_in_trace, packet->location_in_trace, index_of_var + 1);
						pass_verdicts[index_of_var]++;
						current_status[index_of_var] = CURRENT_STATUS_PASS;
						if(--stored_packet->reference_count == 0)//no need for this packet release
							release_runmon_packet((runmon_packet*)linked_list_delete_nth(packet_list, i));
						else
							linked_list_delete_nth(packet_list, i);//not remove the packet itself, but, just from the LL
						pthread_mutex_unlock(lock);
						return FALSE;
					}
                                        node = node->next;
                                        i++;
				}
				pthread_mutex_unlock(lock);
			}
			return FALSE;
		case LN_REQ_NAK_P3:
			index_of_var = 2;
			if(sip->start_line->method != NULL && strcasecmp(sip->start_line->method, "ACK") != 0) //ACK request property 3
                        {
				lock = (pthread_mutex_t*)linked_list_get_nth(saved_messages_locks, index_of_var);
                                pthread_mutex_lock(lock);
                                packet_list = (linked_list*)linked_list_get_nth(saved_messages, index_of_var);
                                packet->reference_count++;
                                linked_list_add(packet_list, packet);
                                pthread_mutex_unlock(lock);
                        }
			return TRUE;
		case LN_RES_NPWT_P3:
 			index_of_var = 2;
			if(sip->start_line->method == NULL && sip->start_line->status_code > 199) //non-provisional response property3
			{
				struct timeval *res = (struct timeval*)malloc(sizeof(struct timeval*));
				struct timeval *time_x = NULL;
				struct timeval *time_y = NULL;
                                void *header_field_value = NULL;
				lock = (pthread_mutex_t*)linked_list_get_nth(saved_messages_locks, index_of_var);
                                pthread_mutex_lock(lock);
				//now search if for the mathing request
                                packet_list = (linked_list*)linked_list_get_nth(saved_messages, index_of_var);
                                i = 0;
                                node = packet_list->head;

                                while (node)
				{
                                        stored_packet = (runmon_packet*)node->element;
                                        stored = (sip_packet*)stored_packet->protocol;
					cseq = NULL; 
					stored_cseq = NULL;
					time_x = stored_packet->time; 
					time_y = packet->time;

                                        if(linked_list_transverse(sip->header_fields, &header_field_value))
                                                if(strcasecmp(((header_field*)header_field_value)->name, "CSeq") == 0)
                                                        cseq = ((header_field*)header_field_value)->value;
                                        while(!cseq && linked_list_transverse(NULL, &header_field_value))
                                                if(strcasecmp(((header_field*)header_field_value)->name, "CSeq") == 0)
                                                        cseq = ((header_field*)header_field_value)->value;

                                        if(linked_list_transverse(stored->header_fields, &header_field_value))
                                                if(strcasecmp(((header_field*)header_field_value)->name, "CSeq") == 0)
                                                        stored_cseq = ((header_field*)header_field_value)->value;
                                        while(!stored_cseq && linked_list_transverse(NULL, &header_field_value))
                                                if(strcasecmp(((header_field*)header_field_value)->name, "CSeq") == 0)
                                                        stored_cseq = ((header_field*)header_field_value)->value;

					if(strcasecmp(stored_cseq, cseq) == 0 && timeval_isgreaterthan(packet->time, stored_packet->time))//both sequence number matches its a response as well for stored sip
					{
						timeval_substract(res, time_y, time_x);
						if(res->tv_sec * 1000000 + res->tv_usec > TIME_CONSTRAINT )//do time constraint if it is a response
						{
							if(DEBUG)
								printf("--FAIL verdict--\n\tMessage(in trace): %i, %i, fails property %i To %ius.\n\n", stored_packet->location_in_trace, packet->location_in_trace, index_of_var + 1, TIME_CONSTRAINT);
							fail_verdicts[index_of_var]++;
							current_status[index_of_var] = CURRENT_STATUS_FAIL;
							//CONSIDER THERE CAN BE AN UPCOMING PACKET THAT FULFILL THIS, but, this is already bigger hence fail
						}
						else
						{
							if(DEBUG)
								printf("--Pass verdict--\n\tMessages(in trace): %i, %i, completes property %i.\n\n", stored_packet->location_in_trace, packet->location_in_trace, index_of_var + 1);
							pass_verdicts[index_of_var]++;
							current_status[index_of_var] = CURRENT_STATUS_PASS;
						}
						if(--stored_packet->reference_count == 0)//no need for this packet release
                                                	release_runmon_packet((runmon_packet*)linked_list_delete_nth(packet_list, i));
						else
							linked_list_delete_nth(packet_list, i);//not remove the packet itself, but, just from the LL
						pthread_mutex_unlock(lock);	
                                                free(res);
						return FALSE;
					}
                                        node = node->next;
                                        i++;
				}
				pthread_mutex_unlock(lock);	
				free(res);	
			}
			return FALSE;
		default:
			return FALSE;
	}
}


struct timeval *last_observed_time; //last observed time
pthread_mutex_t *last_observed_time_lock; //to guarantee thread safe of time reading and writing.

/*
 * process_packet: function that processes each packet
 */

void process_packet(u_char *user_args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
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
	int property_count = *((int*)user_args);
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

	if (pkthdr->len < ETHERNET_HEADER_SIZE)
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

	for (i = 0; i < 2 * VARIBLES_AMMOUNT_TO_BE_SAVED; i++)
		packet_kept |= match_packet_vs_leafnode(i, message);
	if(message->reference_count == 0)
		release_runmon_packet(message);//not interested in this packet
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

int main(int argc, char *argv[])
{
	char *devname = argv[1];
	char *errbuff = (char *) malloc(PCAP_ERRBUF_SIZE); 
	struct pcap_pkthdr *header;
	const u_char *payload;
	still_running = TRUE;
	pthread_t timeout_checker_thread, report_status_thread;
	pthread_mutex_t *lock;
	struct bpf_program fp;
	unsigned long fail_timeout_time = FAIL_TIMEOUT_TIME;
	int i = 0, j =0, properties_count = 1;
	report_status_t *rst = malloc(1 * sizeof(report_status_t));
	int stored_variables_count = VARIBLES_AMMOUNT_TO_BE_SAVED;

	rst->period = REPORT_STATUS_PERIOD;
	rst->properties_count = properties_count;

	linked_list *packet_list = NULL;
	runmon_packet *packet = NULL;

	pcap_t *handler;
	
	if (!(handler = pcap_open_offline(devname,errbuff)))
		 handler = pcap_open_live(devname, BUFSIZ, 1, 1000, errbuff);

	if (handler == NULL)
	{
		printf("Error while opening %s is not a valid filename or device, error: \n\t%s\n", devname, errbuff);
		exit(2);
	}

	if (pcap_compile(handler, &fp, argv[2], 0, PCAP_NETMASK_UNKNOWN) == -1)
	{
		printf("Couldn't parse filter \"%s\": %s\n", argv[2], pcap_geterr(handler));
		exit(2);
	}
 	if (pcap_setfilter(handler, &fp) == -1) 
	{
		printf("Couldn't install filter %s: %s\n", argv[2], pcap_geterr(handler));
		exit(2);
	}

	TIME_CONSTRAINT = atol(argv[3]);

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
	//
	//this should be a function call depending on the var to keep or not the messages
	keep_old_messages[1] = 1;

	last_observed_time = (struct timeval*)malloc(1 * sizeof(struct timeval));
	last_observed_time->tv_sec = 0;
	last_observed_time->tv_usec = 0;
	last_observed_time_lock = (pthread_mutex_t*)malloc(1 * sizeof(pthread_mutex_t));
	pthread_mutex_init(last_observed_time_lock, NULL);
	
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
	
	if (pcap_loop(handler, -1, &process_packet, ((u_char*)&properties_count)) == -1)
		printf("Error occurred in capture!\n%s", pcap_geterr(handler));
	
	still_running = FALSE;

	empty_old_messages(fail_timeout_time);
	empty_old_messages(0);

	i = 0;
	
	print_status(properties_count);
		
	//delete linked lists, nice clean ups
	packet_list = (linked_list*)linked_list_delete(saved_messages);	
	while(packet_list)
	{
		delete_linked_list(packet_list);
		packet_list = (linked_list*)linked_list_delete(saved_messages);
	}

	delete_linked_list(saved_messages);

	//delete locks, nice clean ups
	lock = (pthread_mutex_t*)linked_list_delete(saved_messages_locks);
	pthread_mutex_destroy(lock);
	while(lock)
	{
        	pthread_mutex_destroy(lock);
		lock = (pthread_mutex_t*)linked_list_delete(saved_messages_locks);
	}

	delete_linked_list(saved_messages_locks);	

	free(last_observed_time);	

	pthread_mutex_destroy(last_observed_time_lock);
	
	free(errbuff);
	pcap_close(handler);
	
	free(pass_verdicts);
	free(fail_verdicts);
	
	//pthread_exit(0); //no need to wait for other threads
	return 0;
}
