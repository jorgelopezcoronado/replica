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
#include "packet.h" 

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

/*
 * release_packet: frees packet resources if no longer needed. Important, 
 */
void release_packet(packet* p)
{
	linked_list_node *node = p->dependencies->head;
	linked_list_node *aux = NULL;
	packet *dependency = NULL;
	free(p->time);

      	//free p->protocol 
	
	//free(packet->PO); //CONSIDER THIS AFTER! not sure if you'll use the same string... why not?
	while (node)
	{
		dependency = (packet*)node->element;
		dependency->associations--;
		node = node->next;
	}
	delete_linked_list(p->dependencies);
	
	free(p->pkthdr);
	free(p->data);
	
	free(p);
}

/*
 * match_ports_and_IPs: auxiliary function that helps determine if source port is and dest port matches responses of two packets
 */
BOOL match_ports_and_IPs(packet *p1, packet *p2)
{
	u_short p1sp, p1dp, p2sp, p2dp;
	in_addr_t p1si, p1di, p2si, p2di;

	//if(p1->transport_type != p2->transport_type)
	//	return FALSE; //I'm uncertain if this is actually possible... leave without a check ATM

	p1sp = (p1->transport_type == UDP)?((udph*)p1->transport)->uh_sport:((tcph*)p1->transport)->th_sport;
	p1dp = (p1->transport_type == UDP)?((udph*)p1->transport)->uh_dport:((tcph*)p1->transport)->th_dport;

	p2sp = (p2->transport_type == UDP)?((udph*)p2->transport)->uh_sport:((tcph*)p2->transport)->th_sport;
	p2dp = (p2->transport_type == UDP)?((udph*)p2->transport)->uh_dport:((tcph*)p2->transport)->th_dport;

	p1si = p1->ip->ip_src.s_addr;
	p1di = p1->ip->ip_dst.s_addr;
	
	p2si = p2->ip->ip_src.s_addr;
	p2di = p2->ip->ip_dst.s_addr;

	if (p1sp != p2dp || p1dp != p2sp || p1si != p2di || p1di != p2si)
		return FALSE;

	return TRUE;

}

struct timeval *last_observed_time; //last observed time                                                               |        {
pthread_mutex_t *last_observed_time_lock; //to guarantee thread safe of time reading and writing. 

void process_packet(int property_count, struct pcap_pkthdr *pkthdr, u_char *pkt)
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
	packet *message = (packet*)malloc(sizeof(packet));
	transport_e packet_transport;
	protocol_e packet_protocol;
	int i =0; //DELETE probably since it will be for each leaf not each static leaf
	BOOL packet_kept = FALSE;
	BOOL *completed_properties = (BOOL*)malloc(property_count * sizeof(BOOL));
	u_short source_port = 0, destination_port = 0;
	size_t payload_size = 0;
	
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

	ether = (ethernet_h*)pkt;
	if (ether->ether_type != ETHERNET_IPv4_TYPE)
	{
		//LOG this!
		return;
	}
	
	ip = (ip4*)(pkt + ETHERNET_HEADER_SIZE);
		
	//Leaving this here for future PO cathegorization... 
	inet_ntop(AF_INET, &ip->ip_src, ip_source, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip->ip_dst, ip_dest, INET_ADDRSTRLEN);
	
	if (ip->ip_p == IP_PROTO_UDP)
	{
		udp = (udph*)(pkt + ETHERNET_HEADER_SIZE + (IP_HL(ip) * 4)); //* 4 because size expressed in 32bit 
		payload = (u_char*)(pkt + ETHERNET_HEADER_SIZE + (IP_HL(ip) * 4) + UDP_HEADER_SIZE); //* 4 because size expressed in 32bit  
		packet_transport = UDP;
	}	 
	else if (ip->ip_p == IP_PROTO_TCP)
	{
		tcp = (tcph*)(pkt + ETHERNET_HEADER_SIZE + (IP_HL(ip) * 4)); //* 4 because size expressed in 32bit 
		payload = (u_char*)(pkt + ETHERNET_HEADER_SIZE + (IP_HL(ip) * 4) + (TH_OFF(tcp) * 4)); //* 4 because size expressed in 32bit 
		packet_transport = TCP;
	}
	else
	{
		//LOG this!
		return;
	}

	payload_size = pkthdr->len - (payload - pkt);

	source_port = ntohs((udp)?udp->uh_sport:tcp->th_sport);
        destination_port = ntohs((udp)?udp->uh_dport:tcp->th_dport);
	
	/*EXAMPLE, how to set the point of observation*/
	if(strcmp(ip_source, "62.73.5.128") == 0 || strcmp(ip_dest, "62.73.5.128") == 0 || strcmp(ip_source, "62.73.5.21") == 0 || strcmp(ip_dest, "62.73.5.21") == 0)
		message->PO = "ADS";
	else
		message->PO = "other";


	memset(completed_properties, 0, sizeof(BOOL) * property_count);

	//set protocol in here
	//packet_protocol = ? depending on data? depending on port?
	
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
	message->data = pkt;
		
	switch(packet_transport)
	{
		case UDP:	
			message->transport = udp;
			break;
		default:
			message->transport = tcp;
	}

	//
	printf("%d) length=%d time=%d.%d. from:%s:%d to:%s:%d transport:%s \n", ++count, pkthdr->len, result->tv_sec, result->tv_usec, ip_source, ntohs((udp)?udp->uh_sport:tcp->th_sport), ip_dest, ntohs((udp)?udp->uh_dport:tcp->th_dport), (udp)?"UDP":"TCP"); //interested in all packages?

	//DO SOMETHING WITH THE PACKET, do something with the packet. Store, etc. you can use payload and payload_size	
	//shall we call for an extern function here? like that people can use it

	release_packet(message);
}

void *serve_conn(void *serve_conn_ptr)//make sure this is threadable, should be from the point of view that we are serving different BIOs, but, underlying data structures should be considered
{
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

void print_help(char *progname)
{
	printf("Usage %s: [-h|--help|--h] [-bs buffsize] [-ip ipaddress] [-pt port] <-cf cerfile> <-kf keyfile> ", progname);
	printf("\t\t-h|--help|-h\n\t\t\tPrints this message; the program's help.\n");
	printf("\t\t-bs buffsize [default=2048]\n\t\t\tSize of the buffer for processing the transmited network packets; typically it should be greater than the network's MTU (usually > 1500) + time data (16).\n");
	printf("\t\t-ip ipaddress [default=0.0.0.0, i.e., all ipv4 addresses of the host]\n\t\t\t The IP address to bind the service to.\n");
	printf("\t\t-pt port [default=26965]\n\t\t\t The TCP port to bind the service.\n");
	printf("\t\t-cf certfile\n\t\t\t SSL certificate to serve the connections.\n");
	printf("\t\t-kf keyfile\n\t\t\t private SSL key to serve the connections.\n");
}

unsigned char is_int (char *string)
{
        size_t i = 0;
        while (string[i])
                if(string[i] <= 47 || string[i++] >=58)
                        return 0;
        return 1;
}

char *certificate_file=NULL;
char *private_key_file=NULL;
unsigned int buffersize = 2048;
char *ip_address_string = "0.0.0.0"; 
char *port_string = "26965"; //TSP base 30

void parse_args(char **argv, int argc)
{
	size_t i = 1;

	while(i < argc)
	{
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") || !strcmp(argv[i], "--h")) 
		{
			print_help(argv[0]);
			exit(0);
		}

		else if (!strcmp(argv[i], "-bs"))
		{	
			if (i != argc -1)
			{
				if(! is_int(argv[++i]))
				{
					printf("Error! buffersize, the expected parameter after the -bs flag must be an integer, value: %s\n", argv[i]);
					print_help(argv[0]);
					exit(1);
				}
				sscanf(argv[i], "%lu", &buffersize);
			}
			else 
			{
				printf("Error! expected buffersize after the -bs flag.\n");
				print_help(argv[0]);
				exit(1);	
			}
		}
		
		else if (!strcmp(argv[i], "-ip"))
		{	
			if (i != argc -1)
			{
				//IP function will report error by itself, do not worry about checking the IP format.
				sscanf(argv[++i], "%s", &ip_address_string);
			}
			else 
			{
				printf("Error! expected IP address string after the -ip flag.\n");
				print_help(argv[0]);
				exit(1);	
			}
		}
	
		else if (!strcmp(argv[i], "-pt"))
		{	
			if (i != argc -1)
			{
				if(! is_int(argv[++i]))
				{
					printf("Error! buffersize, the expected parameter after the -pt flag must be an integer, value: %s\n", argv[i]);
					print_help(argv[0]);
					exit(1);
				}
				port_string = (char*)malloc(sizeof(char)*(strlen(argv[i]) + 1));
				strcpy(port_string, argv[i]);
			}
			else 
			{
				printf("Error! expected port number after the -pt flag.\n");
				print_help(argv[0]);
				exit(1);	
			}
		}

		else if (!strcmp(argv[i], "-cf"))
		{	
			if (i != argc -1)
			{
				certificate_file = (char*)malloc(sizeof(char)*(strlen(argv[++i]) + 1));
				strcpy(certificate_file, argv[i]);
			}
			else 
			{
				printf("Error! expected certificate file name (path) after the -cf flag.\n");
				print_help(argv[0]);
				exit(1);	
			}
		}
	
		else if (!strcmp(argv[i], "-kf"))
		{	
			if (i != argc -1)
			{
				private_key_file = (char*)malloc(sizeof(char)*(strlen(argv[++i]) + 1));
				strcpy(private_key_file, argv[i]);
			}
			else 
			{
				printf("Error! expected private key file name (path) after the -kf flag.\n");
				print_help(argv[0]);
				exit(1);	
			}
		}

		else
		{
			printf("Error! unrecognized option: %s.\n", argv[i]);
			print_help(argv[0]);
			exit(1);	
		}


		i++;	
	}

	if (!(certificate_file && private_key_file))
	{
		printf("Error! Certificate file and private key file must be suppled!\n");
		print_help(argv[0]);
		exit(2);
	}
}


	
int main(int argc, char **argv)
{
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
	linked_list *packet_list = NULL;

	parse_args(argv, argc);
	
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
	
	printf("Listening on %s:%i using:\nCertificate file=%s\nPrivate key file=%s\n", ip_address_string, port, certificate_file, private_key_file);

	last_observed_time = malloc(1 * sizeof(struct timeval));
	last_observed_time->tv_sec = 0;
        last_observed_time->tv_usec = 0;
        last_observed_time_lock = (pthread_mutex_t*)malloc(1 * sizeof(pthread_mutex_t));
        pthread_mutex_init(last_observed_time_lock, NULL);
	
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
