#include "helpers.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

/*
 * helpcers.c
 * Helper functions for the project used accross several files.
*/

/*
 * timeval_isgreaterthan takes t1 and t2 pointers and return if t1 > t2
 */
BOOL timeval_isgreaterthan (struct timeval *t1, struct timeval *t2)
{
	return (t1->tv_sec > t2->tv_sec)?TRUE:((t1->tv_sec == t2->tv_sec)?(t1->tv_usec > t2->tv_usec):FALSE);
}

/*
 * timeval_substract takes two values to substract and put the result in the result parameter.
 */
int timeval_substract(struct timeval *result, struct timeval *x, struct timeval *y)
{
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;
	BOOL was_negative = FALSE;

	was_negative = result->tv_sec < 0 || (result->tv_sec == 0 && result->tv_usec < 0);
	
	//if signs differ then should be compensated...		
	if (result->tv_usec && ((result->tv_sec < 0 && result->tv_usec > 0) || (result->tv_sec > 0 && result->tv_usec < 0)))
	{
		result->tv_sec = (result->tv_sec < 0)?result->tv_sec + 1:result->tv_sec - 1;
		result->tv_usec = (result->tv_usec < 0)?1000000 + result->tv_usec:1000000 - result->tv_usec; 
		
	}
	
	result->tv_usec = (result->tv_usec < 0)?-1*result->tv_usec:result->tv_usec;

	if (was_negative)
	{
		result->tv_sec *= -1;
		return 1;
	}
	
	return 0;
		
}

/*
 * bitstream_equal: takes two u_cahr* a lenth and compare them
 */
BOOL bitstream_equal(unsigned char *bs1, unsigned char *bs2, unsigned long long length)
{
	unsigned long long offset = 0;

	//assign to the largest possible data type and bitwise compare, as soon as something is not equal return false or return true if all are equal.
	while (length > 0)
	{
		printf("%c,%c ", *(bs1 + offset), *(bs2 + offset));
		if (length >= sizeof(unsigned long long))
		{
			unsigned long long *bs1_cast, *bs2_cast;
			bs1_cast = (unsigned long long*)(bs1 + offset);
			bs2_cast = (unsigned long long*)(bs2 + offset);
			offset += sizeof(unsigned long long);
			length -= sizeof(unsigned long long);
			if (*bs1_cast ^ *bs2_cast) return FALSE; //The bitwise xor should be 0 all the time if bits are equal... 
		}
		else if (length >= sizeof(unsigned long))
		{
			unsigned long *bs1_cast, *bs2_cast;
			bs1_cast = (unsigned long*)(bs1 + offset);
			bs2_cast = (unsigned long*)(bs2 + offset);
			offset += sizeof(unsigned long);
			length -= sizeof(unsigned long);
			if (*bs1_cast ^ *bs2_cast) return FALSE; //The bitwise xor should be 0 all the time if bits are equal... 
		}
		else if (length >= sizeof(unsigned int))
		{
			unsigned int *bs1_cast, *bs2_cast;
			bs1_cast = (unsigned int*)(bs1 + offset);
			bs2_cast = (unsigned int*)(bs2 + offset);
			offset += sizeof(unsigned int);
			length -= sizeof(unsigned int);
			if (*bs1_cast ^ *bs2_cast) return FALSE; //The bitwise xor should be 0 all the time if bits are equal... 
		}
		else if (length >= sizeof(unsigned short))
		{
			unsigned short *bs1_cast, *bs2_cast;
			bs1_cast = (unsigned short*)(bs1 + offset);
			bs2_cast = (unsigned short*)(bs2 + offset);
			offset += sizeof(unsigned short);
			length -= sizeof(unsigned short);
			if (*bs1_cast ^ *bs2_cast) return FALSE; //The bitwise xor should be 0 all the time if bits are equal... 
		}	
		else
		{
			unsigned char bs1_cast, bs2_cast;
			bs1_cast = *(bs1 + offset);
			bs2_cast = *(bs2 + offset);
			offset += sizeof(unsigned char);
			length -= sizeof(unsigned char);
			if (bs1_cast ^ bs2_cast) return FALSE; //The bitwise xor should be 0 all the time if bits are equal... 
		}
	}
	return TRUE;
}

/*
 * strtrim trims the desired string, beware it modifies the original string.
 */

void strtrim(char **string)
{
	int size = strlen(*string);	
	while(isspace(**string))
		*string += 1 + (size - size--); //increase pointer and decrease size, I know you hate this
	while(isspace(*(*string + size - 1)))
		*(*string + --size) = 0; //decrease size and remove the last character, also hated this of course :p
}

/*
 * print_timeval: easy func to display timeval
 */
void print_timeval(struct timeval* tval, BOOL newline_before, BOOL newline_after)
{
	printf("%s%i.%i%s", (newline_before)?"\n":"", tval->tv_sec, tval->tv_usec, (newline_after)?"\n":"");
}

/*
 * htonll: func to convert to 64 bit host to network order
 */
int64_t htonll (int64_t number)
{
	int64_t endianness_test = 0xFF;

	if(*(char*)&endianness_test == 0xFF)//if the first byte has the lowest value this is litle endian.
		return ((int64_t)htonl(number) << 32) + htonl(number >> 32);
	else 	
		return number;
	
}

int64_t ntohll (int64_t number) //just reverse the order is little endian which is actually the same as htonll
{
	return htonll(number);	
}
