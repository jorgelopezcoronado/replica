/*
 * term.h: file to describe the language formal terms
 * grammar is expressed by the followind BNF
 * 	term :== c | x | x.l1.l2.....ln
 * 		where c is a constant; x is a variable and l is a selector label of a packet 
 */

typedef enum term_data_type_tag
{
	NUMBER = 0,
	STRING = 1,
	VARVAL = 2,
	VARSEL = 3
}term_data_type_e;

typedef struct term_tag
{
	term_data_type_e term_data_type;
	void *value;
}term;
