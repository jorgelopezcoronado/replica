#include <sys/time.h> 

#ifndef BOOL
//code seems cleaner with this boolean representations
#define BOOL unsigned char
#define TRUE 1
#define FALSE 0
#endif

/*
 *  * timeval_substract takes two values to substract and put the result in the result parameter.
 */
int timeval_substract(struct timeval*, struct timeval*, struct timeval*);

/*
 * timeval_isgreaterthan takes t1 and t2 pointers and return if t1 > t2
 */
BOOL timeval_isgreaterthan(struct timeval*, struct timeval*);

/*
 * bitstream_equal: takes two u_cahr* a lenth and compare them
 */
BOOL bitstream_equal(unsigned char*, unsigned char*, unsigned long long); 

/*
 * strtrim trims the desired string, beware it modifies the original string.
 */

void strtrim(char **string);

/*
 * print_timeval: easy func to display timeval
 */
void print_timeval(struct timeval*, BOOL, BOOL);

