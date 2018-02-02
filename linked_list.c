/*
 * linked_list.c: file to define linked list functions 
 */

#include <stdlib.h>
#include <stdio.h>
#include "linked_list.h"
#include "helpers.h"

/*c
 * reate_linked_list: initializes a linked list object
 */

linked_list *create_linked_list()
{
	linked_list *ll = (linked_list*)malloc(sizeof(linked_list));
	if(!ll)
		return NULL;
	ll->head = NULL;
	ll->tail = NULL;
	return ll;
}

/*
 * linked_list_add_front: allocates a node and adds the pointer to the the node and puts this object in front of the LL
 */

BOOL linked_list_add_front(linked_list *ll, void *element)
{
	linked_list_node *node = (linked_list_node*)malloc(sizeof(linked_list_node));
	if(!node)
		return FALSE;
	node->element = element;
	if(!ll->head)//empty list
		ll->tail = node;
	node->next = ll->head;
	ll->head = node;
	return TRUE;
}

/*
 * linked_list_add_end: allocates a node and adds the pointer to the the node and puts this object in last of the LL
 */

BOOL linked_list_add_end(linked_list *ll, void *element)
{
	linked_list_node *node = (linked_list_node*)malloc(sizeof(linked_list_node));
        if(!node)
                return FALSE;
	node->element = element;
	if(!ll->head)
		ll->tail = ll->head = node;
	else
		ll->tail->next = node;
	ll->tail = node;
	node->next = NULL;
	return TRUE;
}

/*
 * linked_list_get_front: gets the first element of the list 
 */
void *linked_list_get_front(linked_list *ll)
{
	if (ll->head)
		return ll->head->element;
	return NULL;
}

/*
 * linked_list_get_end: gets the last element of the list
 */
void *linked_list_get_end(linked_list *ll)
{
	if(ll->tail)
		return ll->tail->element;
	return NULL;
}

/*
 * linked_list_get: default linked list get
 */

void *linked_list_get(linked_list *ll)
{
	return linked_list_get_front(ll);
}

/*
 * linked_list_get_nth: gets the nth element of the list, by using this you need to loop though the entire 
 */
void *linked_list_get_nth(linked_list *ll, unsigned int n)
{
	int i = 0;
	linked_list_node *node = ll->head;
	if (n == 0)
		return linked_list_get_front(ll);
	//if doing the loop for the last it doesn't matter to save this with the size verification I'll return null in case
	while (node && i <= n)
	{
		if(i++ == n)
			return node->element;
		else
			node = node->next;
	}
	return NULL;
}

/*
 * linked_list_transverse: function useful to get all elements of the list whithot doing too much lopps or knowing about internal structure
 */

BOOL linked_list_transverse (linked_list *ll, void **result)
{
	static linked_list_node *node = NULL;	
	if (!ll)
	{
		if (node)
		{
			node = node->next;
			if(node)
			{
				*result = node->element;
				return TRUE;
			}
		}
	}
	else
	{
		node = ll->head;
		if (node)
		{
                	*result = node->element;
                	return TRUE;
               }	
	}
	result = NULL;
	return FALSE;
}

/*
 * linked_list_delete_font: deallocates de node memory and re-adjusts the linked list node pointers while returning the deleted object 
 */

void *linked_list_delete_front(linked_list *ll)
{
	void *element = NULL;
	linked_list_node *node = NULL;
	if(!ll->head)
		return NULL;
	node = ll->head;
	element = node->element; 
	ll->head = node->next;
	if(!ll->head)
		ll->tail = NULL;
	free(node);
	return element;
}

/*
 * linked_list_delete_last: deallocates de node memory and re-adjusts the linked list node pointers while returning the deleted object 
 */

void *linked_list_delete_end(linked_list *ll)
{
	void *element = NULL;
        linked_list_node *node = NULL;
	linked_list_node *aux = ll->head;
	if(!ll->head)
        	return NULL;
        node = ll->tail;
	element = node->element;
	if(ll->head == ll->tail) // list of one element easy to delete without cycling
	{
		ll->tail = ll->head = NULL;
		free(node);
		return element;
	}
	
	while(aux->next != ll->tail) 
		aux = aux->next; //move pointer to delete
			
	aux->next = NULL;	
		
	free(node);
	ll->tail = aux;
		
	return element;
}

/*
 * linked_list_size: returns the ammount of elements in the linked list;
 */

int linked_list_size(linked_list *ll)
{
	linked_list_node *node = ll->head;
	int size = 0;
	while(node != NULL)	
	{
		node = node->next;
		size++;
	}
	return size;
}

/*
 * linked_list_add_nth: function to insert on the linked list at a given position
 */

BOOL linked_list_add_nth(linked_list *ll, void *element, unsigned int position)
{
	int size = linked_list_size(ll);
	linked_list_node *aux = ll->head;
	linked_list_node *node = NULL;
	int pos = 0;
	if (position > size) //can't be considered less than 0 :p
		return FALSE;

	if (position == 0)
		return linked_list_add_front(ll, element);

	if (position == size)
		return linked_list_add_end(ll, element);
	
	node = (linked_list_node*)malloc(sizeof(linked_list_node));
	if(!node) 
		return FALSE;
	
	node->element = element;	

	while (++pos != position)
		aux = aux->next; 

	node->next = aux->next;
	aux->next = node;
	
	return TRUE;	
}

/*
 * linked_list_delete_nth: function to delete from a specific position
 */

void *linked_list_delete_nth(linked_list *ll, unsigned int position)
{
	int size = linked_list_size(ll);
        linked_list_node *aux = ll->head, *aux2;
        linked_list_node *node = NULL;
        int pos = 0;
	void *element = NULL;
	
        if (position >= size) //can't be considered less than 0 :p
                return NULL;

	if (position == 0)
                return linked_list_delete_front(ll);

        if (position == size - 1)
                return linked_list_delete_end(ll);

	while (++pos != position)
                aux = aux->next;

	aux2 = aux->next;

	aux->next = aux2->next;
	aux2->next = NULL;
	element = aux2->element;
	free(aux2);

	return element;
}

/*
 * linked_list_insert: default way to insert
 */

BOOL linked_list_add(linked_list *ll, void *element)
{
	return linked_list_add_front(ll, element);
}

/*
 * linked_list_delete: default way to delete
 */

void *linked_list_delete(linked_list *ll)
{
	return linked_list_delete_front(ll);
}

/*
 * delete_linked_list: deletes/frees a linked list, first deallocates all it's objects, so be careful using it, you might create a memory leak:p
 */

void delete_linked_list(linked_list *ll)
{
	linked_list_node *aux = ll->head;
	while (aux != NULL)
	{
		ll->head = ll->head->next;
		free(aux);	
		aux = ll->head;
	}
	free(ll);
}
/*
 * linked_list_perform_action: performs the function action to each element on the list
 */

void linked_list_perform_action(linked_list *ll, void (*function)(void*))
{
	linked_list_node *node = ll->head;
	while(node != NULL)
	{
		function(node->element);
		node = node->next;
	}
	
}
