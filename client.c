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
#include <pcap.h>
#include "helpers.h" 
#include <netinet/in.h>

#define DEBUG 1

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

BIO* connect_enctypted (char *host_port, char *store_path, BOOL store_type_file, SSL_CTX **ctx, SSL **ssl, BOOL strict_cert_check)
{
	BIO *bio = NULL;
	int store_path_error = 0;

	*ctx = SSL_CTX_new(SSLv23_client_method());
	*ssl = NULL;

	if (!(*ctx))
	{
		report_error("Unable to allocate SSL context pointer.\n", NULL);
		return NULL;
	}
	
	if (store_type_file)
		store_path_error = SSL_CTX_load_verify_locations(*ctx, store_path, NULL);
	else // store path dir
		store_path_error = SSL_CTX_load_verify_locations(*ctx, NULL, store_path);

	if(!store_path_error)
	{
		report_error("Unable to load trust store %s.\n", store_path);
		SSL_CTX_free(*ctx);
		return NULL;
	}
	
	bio = BIO_new_ssl_connect(*ctx);
	if(!bio)
	{
		report_error("Unable to allocate BIO pointer.\n", NULL);
		SSL_CTX_free(*ctx);
                return NULL;
	}

	BIO_get_ssl(bio, ssl);
    	if (!*ssl) 
	{
		report_error("Unable to allocate SSL pointer.\n", NULL);
		SSL_CTX_free(*ctx);
		BIO_free_all(bio);
		return NULL;
	}
	
	SSL_set_mode(*ssl, SSL_MODE_AUTO_RETRY);
	BIO_set_conn_hostname(bio, host_port);
	if(BIO_do_connect(bio) <= 0)
	{
		report_error("Unable to connect BIO %s\n", host_port);
		SSL_CTX_free(*ctx);
                BIO_free_all(bio);
        	return NULL;
	}
	
	if(strict_cert_check && SSL_get_verify_result(*ssl) != X509_V_OK) 
	{
		report_error("Certificate verification failure.  Specifiy strict_cert_check = false to skip allow untrusted certificates or verify your certificate file\n", NULL);
                SSL_CTX_free(*ctx);
                BIO_free_all(bio);
                return NULL;
	}

	//all good at this point...
	return bio;
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
			report_error("Read error, BIO_should_retry error", NULL);
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
			report_error("Write error, BIO_should_retry error", NULL);
			return written_bytes;
		}
	}
	
	return written_bytes;
}

char *get_final_pcap_filter(char *pcap_filter, char *host, char *port)
{
	const char *not_host = "!(dst host ", *not_port = " && dst port ", *and = ") && ";
	char *final_filter = (char*)malloc(sizeof(char) * (strlen(not_host) + strlen(host) + strlen(not_port) + strlen(port) + strlen(and) + strlen(pcap_filter) + 1)); 
	
	strcpy(final_filter, not_host);
	strcat(final_filter, host);
	strcat(final_filter, not_port);
	strcat(final_filter, port);
	
	if(pcap_filter == NULL)	
		return final_filter;//in good theory wasted space for the missing " and " here, but, it's alright for the time being...	

	strcat(final_filter, and);
	strcat(final_filter, pcap_filter);
	
	return final_filter; 
}

char *get_host_port (char *host, char *port)
{
	const char *separator = ":";
	char *host_port = (char*)malloc(sizeof(char) * (strlen(host) + strlen(port) + strlen(separator) + 1));

	strcpy(host_port, host);
	strcat(host_port, separator);
	strcat(host_port, port);
	
	return host_port;
	
}

void process_packet(u_char *user_args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	BIO *bio = (BIO*)user_args;
	//let us assume that the SSL mode auto rety set before will deal with re-connections, we will try...
	char *buff = NULL;	
	uint64_t aux_long;
	char nl = '\n';
	u_char size = sizeof((pkthdr->ts.tv_sec));
	uint32_t aux_int;

	buff = (char*)&size;
	write_to_stream(bio, buff, 1);

	if(size == sizeof(int64_t))
	{
		aux_long = htonll(pkthdr->ts.tv_sec);
		buff = (char*)&aux_long;
	}
	else
	{
		aux_int = htonl(pkthdr->ts.tv_sec);
		buff = (char*)&aux_int;
	}
	write_to_stream(bio, buff, size);
	
	size = sizeof((pkthdr->ts.tv_usec));
	buff = (char*)&size;
	write_to_stream(bio, buff, 1);

	if(size == sizeof(int64_t))
        {
                aux_long = htonll(pkthdr->ts.tv_usec);
                buff = (char*)&aux_long;
        }
        else
        {
                aux_int = htonl(pkthdr->ts.tv_usec);
                buff = (char*)&aux_int;
        }
        write_to_stream(bio, buff, size);
	//sent sizeof(tv_sec), tv_sec, siseof(tv_usec), tv_usec
	aux_int = htonl(pkthdr->caplen);
	buff = (char*)&aux_int;
	write_to_stream(bio, buff, sizeof(int32_t));
	
	aux_int = htonl(pkthdr->len);
        buff = (char*)&aux_int;
        write_to_stream(bio, buff, sizeof(int32_t));
	//setn all packet header here.
	
	//let's transfer the data per-se now...
	buff = (char*)packet;
	write_to_stream(bio, buff, pkthdr->caplen);
	
}

int main(char **argv, int argc)
{
	//all this params should be read from a conf file...
	char *host = "tilidom4.tilidom.com";
	char *port = "26965";
	char *store_path = "/etc/pki/tls/certs/ca-bundle.crt";
	BOOL store_type_file = TRUE;
	BOOL strict_cert_check = FALSE; 
	int buffersize = 4096;
	char *pcap_filter = "port 53";
	char *devname = "eth0";
	
	//...............
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	BIO *bio = NULL;
	ssize_t operation_length = 0;
	char *final_pcap_filter, *host_port; 
	char *buffer = (char*)malloc(buffersize * sizeof(char));
	char *outgoing_message = "GET / HTTP/1.1\nHost: www.verisign.com\nConnection: Closed\n\n";
	char *errbuff = (char *) malloc(PCAP_ERRBUF_SIZE);
	pcap_t *handler = NULL;
	struct bpf_program fp;

	final_pcap_filter = get_final_pcap_filter(pcap_filter, host, port); 

	host_port = get_host_port(host, port);
	debug = DEBUG;

	if (!(handler = pcap_open_offline(devname,errbuff)))
                 handler = pcap_open_live(devname, BUFSIZ, 1, 1000, errbuff);

        if (handler == NULL)
        {
                printf("Error while opening %s is not a valid filename or device, error: \n\t%s\n", devname, errbuff);
                exit(2);
        }

	
	if (pcap_compile(handler, &fp, final_pcap_filter, 0, PCAP_NETMASK_UNKNOWN) == -1)
        {
                printf("Couldn't parse filter \"%s\": %s\n", final_pcap_filter, pcap_geterr(handler));
                exit(2);
        }
        if (pcap_setfilter(handler, &fp) == -1)
        {
                printf("Couldn't install filter %s: %s\n", pcap_filter, pcap_geterr(handler));
                exit(2);
        }
	
	init_ssl();
	
	bio = connect_enctypted(host_port, store_path, store_type_file, &ctx, &ssl, strict_cert_check);
	if(!bio)
		exit(3);
	
	if (pcap_loop(handler, -1, &process_packet, ((u_char*)bio)) == -1)
                printf("Error occurred in capture!\n%s", pcap_geterr(handler));

	free(errbuff);
        pcap_close(handler);

}
