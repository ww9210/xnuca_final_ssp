#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
struct ppl_list_node{
    struct ppl_list_node *fd;
    struct ppl_list_node *bk;
};

void ppl_node_unlink(struct ppl_list_node * node){
    struct ppl_list_node * FD = node->fd;
    struct ppl_list_node * BK = node->bk;
    BK->fd = FD;
    FD->bk = BK;
}

void list_insert(struct ppl_list_node * head,  struct ppl_list_node * node){
    struct ppl_list_node * FD = head->fd;
    //struct ppl_list_node * BK = head->bk;
    head->fd = node;
    node->fd = FD;
    node->bk = head;
    FD->bk = node;
}

struct executor_queue;

struct ppl_list_node head;

struct executor_ops{
    void (*executor_free)(struct executor_queue * eq);
    int (*push_elem)(struct executor_queue* eq, void *value);
    int (*pop_elem)(struct executor_queue * eq, void *value);
    int (*get_elem)(struct executor_queue * eq, void *value);
    int (*check_patch)(struct executor_queue *eq, void *value);
    int (*run_patch)(struct executor_queue * eq, void * value);
};

struct patch_attr{
    unsigned int queue_type;
    unsigned int max_queue_entries;
    unsigned int value_size;
    unsigned int timeout;
    unsigned int number_of_patch;
    unsigned int idx_to_swap;
};

struct executor_queue{
    const struct executor_ops *ops;
    unsigned int queue_type;
    unsigned int executor_idx;
    unsigned int max_queue_entries;
    unsigned int value_size;
    unsigned int head, tail;
    unsigned int size;
    struct ppl_list_node list;
    char elements[0];
};

int recv_until(char* buf,int size,char end){
    char tmp;
    int i;
    for(i=0;i<size;i++){
        read(0,&tmp,1);
        if(tmp==end){
            break;
        }
        buf[i]=tmp;
    }
    buf[i+1]=='\x00';
    return i;
}
