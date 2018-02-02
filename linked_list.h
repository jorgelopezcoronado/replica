/*
 * linked_list.c: file to define linked list functions 
 */

#include "linked_list_node.h"
#include "helpers.h"

/*
 * struct definition of linked list object
 */

#ifndef linked_list
typedef struct linked_list_tag
{
	linked_list_node *head;
	linked_list_node *tail;
}linked_list;
#endif
/*c
 * reate_linked_list: initializes a linked list object
 */

linked_list *create_linked_list();

/*
 * linked_list_add_front: allocates a node and adds the pointer to the the node and puts this object in front of the LL
 */

BOOL linked_list_add_front(linked_list *ll, void *element);

/*
 * linked_list_add_end: allocates a node and adds the pointer to the the node and puts this object in last of the LL
 */

BOOL linked_list_add_end(linked_list *ll, void *element);

/*
 * linked_list_delete_font: deallocates de node memory and re-adjusts the linked list node pointers while returning the deleted object 
 */

void *linked_list_delete_front(linked_list *ll);

/*
 * linked_list_delete_last: deallocates de node memory and re-adjusts the linked list node pointers while returning the deleted object 
 */

void *linked_list_delete_end(linked_list *ll);

/*
 * linked_list_size: returns the ammount of elements in the linked list;
 */

int linked_list_size(linked_list *ll);

/*
 * linked_list_add_nth: function to insert on the linked list at a given position
 */

BOOL linked_list_add_nth(linked_list *ll, void *element, unsigned int position);

/*
 * linked_list_get_front: gets the first element of the list 
 */
void *linked_list_get_front(linked_list *ll);

/*
 * linked_list_get_end: gets the last element of the list
 */
void *linked_list_get_end(linked_list *ll);

/*
 * linked_list_get_nth: gets the nth element of the list, by using this you need to loop though the entire 
 */
void *linked_list_get_nth(linked_list *ll, unsigned int n);

/*
 * linked_list_get: default linked list get
 */

void *linked_list_get(linked_list *ll);

/*
 * linked_list_transverse: function useful to get all elements of the list whithot doing too much lopps or knowing about internal structure
 */

BOOL linked_list_transverse (linked_list *ll, void **result);


/*
 * linked_list_delete_nth: function to delete from a specific position
 */

void *linked_list_delete_nth(linked_list *ll, unsigned int position);

/*
 * linked_list_insert: default way to insert
 */

BOOL linked_list_add(linked_list *ll, void *element);

/*
 * linked_list_delete: default way to delete
 */

void *linked_list_delete(linked_list *ll);

/*
 * delete_linked_list: deletes/frees a linked list, first deallocates all it's objects, so be careful using it, you might create a memory leak:p
 */

void delete_linked_list(linked_list *ll);

/*
 * linked_list_perform_action: performs the function action to each element on the lists */

void linked_list_perform_action(linked_list *ll, void (*function)(void*));
