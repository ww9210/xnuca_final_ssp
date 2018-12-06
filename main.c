/* author: ww9210
 * title: ssp
 * description: x-nuca online patch system
 * date: 2018.11.26
 * vul type 1: integer overflow to buffer overflow
 * vul type 2: use after free
 * vul type 3: stack overflow
 * vul type 4: info leak
 */

//#define DEBUG 1
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "sha3.h"
#include "flag.h"
#include "utils.h"
#include "elf.h"

// macro definitions
#define ELF_EXECUTOR 0
#define PYTHON_EXECUTOR 1
#define BRAINFUCK_EXECUTOR 2
#define ELF_PROGRAM_NAME "./samples/helloworld"

// global variables
char flag[FLAGLENGTH+1];
char sha3_hash[65];
FILE *flag_fp;
unsigned int total_ppl;
char* elf_unpatched;
unsigned int elf_unpatched_size;
char* py_unpatched;
const char charset[]="abcdefghijklmnopqrstuvwxyz"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "1234567890";
int global_executor_idx=0;

/* function declaration */
int swap_a_patch();
int upload_patches();
int run_patches();
int add_patch_pipeline();
int add_complain();
int remove_pipeline();
#ifdef DEBUG
void get_shell();
#endif 

void elf_executor_free(struct executor_queue*);
int elf_push_elem(struct executor_queue* , void*);
int elf_pop_elem(struct executor_queue* , void*);
int elf_get_elem(struct executor_queue* , void*);
int elf_check_patch(struct executor_queue*, void*);
int elf_run_patch(struct executor_queue*, void*);

const struct executor_ops elf_executor_ops = {
    .executor_free = elf_executor_free,
    .push_elem = elf_push_elem,
    .pop_elem = elf_pop_elem,
    .get_elem = elf_get_elem,
    .check_patch = elf_check_patch,
    .run_patch = elf_run_patch,
};

int safe_read(int fd, char* buffer, unsigned int size){
    int total, tmp;
    total = 0;
    tmp = 0;
    while(total < size){
        tmp = read(fd, buffer+total,size-total);
        if(tmp<0){
            exit(0);
        }
        total+=tmp;
        if(total==size){
            break;
        }
    }
    return total;
}

void dump_program_header_entry(ELF64_FileRef file, ELF64_HeaderRef header){
    ELF64_ProgramHeaderEntryRef pHeader;
    ELF64_SectionHeaderEntryRef sHeader;
    ELF64_Half i;
    for( i = 0; i < ELF64_HeaderGetProgramHeaderEntryCount( header ); i++ )
    {
        pHeader = ELF64_FileGetProgramHeaderEntry( file, i );
        
        printf
        (
            "    ### Program header entry (%lu):\n"
            "    \n"
            "        - Segment type:                %s\n"
            "        - Segment attributes:          %lu (%s)\n"
            "        - Offset in file:              0x%016lx\n"
            "        - Virtual address in memory:   0x%016lx\n"
            "        - Size of segment in file:     %lu\n"
            "        - Size of segment in memory:   %lu\n"
            "        - Alignment of segment:        %lu\n"
            "    \n",
            ( unsigned long )i,
            ELF64_ProgramHeaderEntryGetTypeString( pHeader ),
            ( unsigned long )ELF64_ProgramHeaderEntryGetAttributes( pHeader ),
            ELF64_ProgramHeaderEntryGetAttributesString( pHeader ),
            ELF64_ProgramHeaderEntryGetFileOffset( pHeader ),
            ELF64_ProgramHeaderEntryGetMemoryVirtualAddress( pHeader ),
            ( unsigned long )ELF64_ProgramHeaderEntryGetFileSize( pHeader ),
            ( unsigned long )ELF64_ProgramHeaderEntryGetMemorySize( pHeader ),
            ( unsigned long )ELF64_ProgramHeaderEntryGetAlignment( pHeader )
        );
    }
   
    for( i = 0; i < ELF64_HeaderGetSectionHeaderEntryCount( header ); i++ )
    {
        sHeader = ELF64_FileGetSectionHeaderEntry( file, i );

        printf
        (
            "    ### Section header entry (%lu):\n"
            "    \n"
            "        - Section name:                            %s\n"
            "        - Section type:                            %s\n"
            "        - Section attributes:                      %lu (%s)\n"
            "        - Virtual address in memory:               0x%016lx\n"
            "        - Offset in file:                          %lu\n"
            "        - Size of section:                         %lu\n"
            "        - Link to other section:                   %lu\n"
            "        - Miscellaneous information:               %lu\n"
            "        - Address alignment boundary:              %lu\n"
            "        - Size of entries, if section has table:   %lu\n"
            "    \n",
            ( unsigned long )i,
            ELF64_FileGetNameOfSection( file, sHeader ),
            ELF64_SectionHeaderEntryGetTypeString( sHeader ),
            ( unsigned long )ELF64_SectionHeaderEntryGetAttributes( sHeader ),
            ELF64_SectionHeaderEntryGetAttributesString( sHeader ),
            ELF64_SectionHeaderEntryGetMemoryVirtualAddress( sHeader ),
            ( unsigned long )ELF64_SectionHeaderEntryGetFileOffset( sHeader ),
            ( unsigned long )ELF64_SectionHeaderEntryGetSectionSize( sHeader ),
            ( unsigned long )ELF64_SectionHeaderEntryGetLinkedSectionIndex( sHeader ),
            ( unsigned long )ELF64_SectionHeaderEntryGetMiscInfo( sHeader ),
            ( unsigned long )ELF64_SectionHeaderEntryGetAddressAlignmentBoundary( sHeader ),
            ( unsigned long )ELF64_SectionHeaderEntryGetEntrySize( sHeader )
        );
    }
}

int elf_check_patch(struct executor_queue* eq, void* value){
    // get different size
    int i;
    int diff = 0;
    int fail = 0;
    char* pv = (char*)value; // patched version

    for(i = 0; i < elf_unpatched_size; i++){
        if(pv[i] != elf_unpatched[i]){
            diff++;
        }
        if(diff > 0x100){
            break;
        }
    }

#ifdef DEBUG
    printf("diff: %d\n",diff);
#endif
    if(diff > 0x100){
        fail = 1;
    }

    // check elf header        
    // todo
    ELF64_FileRef file;
    ELF64_HeaderRef header;
    file = ELF64_ReadFromData(pv);
    header = ELF64_FileGetHeader(file);
    if( ELF64_FileIsValid(file) == false){
        puts("bad elf :(");
        fail = 1;
    }
    dump_program_header_entry(file, header);
    if(fail){
        return -1;
    }

    return 0;
}

void rand_str(char *dest, unsigned char* seed, unsigned int size){
    int i;
    unsigned char index;
    for(i=0; i < size; i++){
        index = seed[i] % 62;
#ifdef DEBUG
        //printf("%d,%c ",index, charset[index]);
#endif
        dest[i] = charset[index];
    }
    dest[size]='\x00';
}

int elf_run_patch(struct executor_queue* eq, void* value){
    // get random string
    int byte_cnt = 31;
    char data[32];
    char dirname[32];
    FILE* fp;
    char *target = "/helloworld";
    char *args[] = {target, NULL};
    char cmd[64];
    int res;
    char cwd[PATH_MAX];

    memset(cmd,0,64);
    fp = fopen("/dev/urandom", "r");
    fread(&data, 1, byte_cnt, fp);
    fclose(fp);
    fp=NULL;
    rand_str(dirname, data, byte_cnt);  

#ifdef DEBUG
    printf("dirname is %s\n", dirname);
#endif

    //mkdir 
    mkdir(dirname, 0777);

    // fork
    pid_t pid, wpid;
    int status;
    pid = fork();
    if(pid==0){ //child
#ifdef DEBUG
        //printf("child on\n");
#endif
        if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
#ifdef DEBUG
            printf("namespace fail\n");
#endif
            perror("unshare: ");
            exit(1);
        }
        res=chroot(dirname);
        if(res<0){
            perror("chroot:");
#ifdef DEBUG
            printf("chroot fail\n");
#endif
            exit(1);
        } 
#ifdef DEBUG
        /*
        printf("current effective uid %d \n",(int)geteuid());
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            printf("Current working dir: %s\n", cwd);
        }
        else{
            perror("getcwd() error");
            exit(0);
       }
       */
#endif
        // write patched executable to disk
        //strcpy(cmd, dirname);
        strcat(cmd, "/helloworld");
        fp = fopen(cmd,"wb");
        if(fp<0){
            perror("fopen");
            exit(0);
        }
        fwrite((char*)value, 1, elf_unpatched_size, fp);
        fclose(fp);
        chmod("/helloworld", 0777);
        // execve it
        system("id");
        res=execve(target ,args, NULL);
        if(res<0){
            perror("execve:");
            printf("execve fail\n");
        }
        exit(0);
    }
    wait(&status);
    strcpy(cmd, "rm -r ");
    strcat(cmd, dirname);
#ifdef DEBUG
    printf("%s\n",cmd);
#endif
    system(cmd);
    return 0; 
}

void elf_executor_free(struct executor_queue* eq){
    short buffer_size=0;
    free(eq);
    ppl_node_unlink(&eq->list);
    puts("feedback?");
    read(0, &buffer_size, 2);
    char *buffer = malloc((unsigned int)buffer_size);
    read(0, buffer, buffer_size);
    puts("thanks for the feedback, we will definitely read it");
    free(buffer);
    return;
}

int elf_push_elem(struct executor_queue* eq, void* value){
    void * dst;
    dst = &eq->elements[eq->head * eq->value_size];
    memcpy(dst, value, eq->value_size);
    if(++eq->head > eq->max_queue_entries){
        eq->head = 0;
    }
#ifdef DEBUG
    printf("succesfully pushed new element of %d bytes to: %p \n", eq->value_size, dst);
#endif
    return 0;
}

int elf_pop_elem(struct executor_queue* eq, void* value){
    if(eq->head==0){
        return -1 ;
    }
    eq->head -= 1;
    return 0;
}

int elf_get_elem(struct executor_queue* eq, void* value){
    if(eq->tail == eq->head){
        return -1;
    }
    memcpy(value, (char*)eq->elements + eq->tail * eq->value_size, eq->value_size);
    //eq->tail += 1;
    return 0;
}


int check_patch_attr(struct patch_attr* attr){

    /* check the whether these arguments are valid */

    if(attr->queue_type > BRAINFUCK_EXECUTOR){
        return -2;
    }

    if(attr->value_size > 0x100000){
        return -1;
    }

    if(total_ppl > 3)
    {
        printf("too many:(\n");
        return -3;
    }

    return 0;
}

/* executor queue initialization */
void init_executor_queue(struct executor_queue* eq, struct patch_attr *attr){
    eq->queue_type = attr->queue_type;
    eq->max_queue_entries = attr->max_queue_entries;
    eq->value_size = attr->value_size;
    eq->executor_idx = global_executor_idx;
    eq->head = 0;
    eq->tail = 0;
    return;
}


unsigned int* safe_read_flag()
{
    flag_fp = fopen(FLAGPATH,"rb");
	if(flag_fp<0){
		perror("fopen");
		exit(1);
	}
	unsigned int *p = (unsigned int *)sha3_hash;
	sha3_ctx ctx;
	memset(sha3_hash,0,65);
	fread(flag, FLAGLENGTH, 1, flag_fp);
	flag[FLAGLENGTH]='\x00';
#ifdef DEBUG
	printf("%s\n",flag);
#endif
	rhash_sha3_256_init(&ctx);
	rhash_sha3_update(&ctx, (const unsigned char*)flag, FLAGLENGTH);
	rhash_sha3_final(&ctx,(unsigned char*)sha3_hash);
	printf("sha3 of flag: %x %x %x %x %x %x %x %x\n",p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7]);

	memset(flag,0,FLAGLENGTH);
    return p;
}
void welcome(){
    printf("CTF players, welcome to X-NUCA 2018! Someone insists all teams should not have direct access to the gamebox, because we do not want some general protection scheme to ruin the game. As a result, ww9210 has to implement this super secure patcher (SSP) to faciliate the process of patching and evaluation locally\n");
}

void print_options(){
    puts("[u] upload patches");
    puts("[c] complain");
    puts("[a] add patch pipeline");
    puts("[s] swap a patch");
    puts("[e] exit");
    puts("[r] run patches");
    puts("[d] remove a pipeline");
}


void read_original_program(){
    struct stat st;
    elf_unpatched=NULL;
    py_unpatched=NULL;
    int elfsize = 0;
    int ret = stat(ELF_PROGRAM_NAME, &st);
    if(ret<0){
        puts("elf file not exist");
        exit(0);
    }

    elfsize = st.st_size; 
    elf_unpatched_size = elfsize;
    FILE *fp = fopen(ELF_PROGRAM_NAME, "rb");
    elf_unpatched = malloc(elfsize);
    fread(elf_unpatched, 1, elfsize , fp);
    fclose(fp);
#ifdef DEBUG
    printf("%d, %s\n",elfsize, elf_unpatched);
#endif
    return; 
}
//static char stdin_buf[50000];
int main()
{
    int ret;
    char buffer[16];
    char* option_buffer = buffer;
    unsigned int* flag_hash;
    total_ppl = 0;
    head.fd = &head;
    head.bk = &head;

    alarm(30);
    //setvbuf(stdin, stdin_buf, _IOFBF, sizeof(stdin_buf));
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
#ifdef DEBUG
    printf("%d\n",getpid());
#endif
    read_original_program();
    welcome();    
    flag_hash=safe_read_flag();
    if(flag_hash[0] % 3 == 1){
        option_buffer = malloc(16);
    }
    print_options();

    while(global_executor_idx < 5){
        memset(option_buffer,0,16);
        printf("$ ");
        recv_until(option_buffer,16,'\n');
        switch(option_buffer[0]){
            case 'a':
                ret=add_patch_pipeline();
                if(!ret){
                    if(ret==-1){
                        puts("invalid pipeline size");
                        exit(0);
                    }
                    if(ret==-2){
                        puts("invalid pipeline type");
                        exit(0);
                    }
                    if(ret==-9){
                        puts("cost too high");
                        exit(0);
                    }
                    if(ret==-8){
                        puts("malloc fail");
                        exit(0);
                    }
                }
                break;
            case 'c': // complain 
                ret=add_complain();
                break;
            case 'u': // upload a patch
                ret=upload_patches();
                break;
            case 's': // swap a patch
                ret=swap_a_patch();
                break;
            case 'e': // exit
                puts("bye");
                exit(0);
                break;
            case 'r': // run patches
                ret=run_patches();
                break;
            case 'd': // remove a patch pipeline
                ret=remove_pipeline();
                break;
#ifdef DEBUG
            case 'x': // get shell
                get_shell();
                break;
#endif
            default:
                printf(option_buffer, option_buffer, option_buffer, option_buffer, option_buffer, option_buffer, option_buffer, option_buffer, option_buffer); // leak heap pointer
                printf(" :invalid option.\n");
                break;

        }
    }
}

int add_complain(){
    char option_buffer[16];
    char *message;
    memset(option_buffer, 0, 16);
    puts("Anything to complain about your patch?");
    puts("1. My patch is checked down but it should work.");
    puts("2. My patch seems not effective against some team.") ;
    puts("3. other complains");
    recv_until(option_buffer, 16, '\n');
    switch(option_buffer[0]){
        case '1':
            puts("We have a checker to check the function of the target program, your patch should not change those basic behaviors, also we disallow too many change over the original program.");
            break;
        case '2':
            puts("Maybe they are attacking your service with a deeper vulnerability, come on bro");
            break;
        case '3':
            message = malloc(0x200);
            read(0,message,0x200);
            puts("thanks for the complain, we will get back to you in a second");
            sleep(1);
            if(strstr(message,"flag") > 0){
                printf("%s, Your complain looks reasonable, let us give you a stack overflow as reward :n\n",message);
                free(message);
                read(0, option_buffer, 0x200);
                exit(0);
            }
            break;
        default:
            break;
    }
}

struct executor_queue * do_patch_pipeline_alloc(struct patch_attr* attr){
    unsigned int size, value_size; 
    unsigned long queue_size, cost;

    struct executor_queue * eq;
    size = attr->max_queue_entries + 1;
    value_size = attr->value_size;
    queue_size = sizeof(*eq) + (unsigned long) value_size * size;
    cost = queue_size + (0x1000 - (queue_size % 0x1000));
    if (cost >= 0x10000000){
        return NULL;
    }
    eq = malloc(queue_size);
    if(eq<0){
        return NULL;
    }
    eq->ops = &elf_executor_ops;
    init_executor_queue(eq, attr);
    eq->size = size;
    return eq;
}

int add_patch_pipeline(){
    struct patch_attr* attr; int res = 0;
    struct executor_queue *eq;
    puts(">");
    attr = malloc(sizeof(struct patch_attr));
    read(0, attr, sizeof(struct patch_attr));
#ifdef DEBUG
    puts("o");
#endif

    res=check_patch_attr(attr);
    if(res<0){
#ifdef DEBUG
        printf("check patach attr error code: %d\n",res);
#endif
        return res;
    }

    eq = do_patch_pipeline_alloc(attr);
    if(!eq){
#ifdef DEBUG
        printf("pipeline alloc error\n");
#endif
        return res;
    }

    list_insert(&head, &eq->list);
    total_ppl+=1;
    global_executor_idx+=1;
#ifdef DEBUG
    printf("successfully added pipeline\n");
#endif

    return res;
}

int remove_pipeline(){
    struct executor_queue *eq = NULL;
    struct ppl_list_node * cur; 
    unsigned int idx;
    read(0, &idx, 4);
    cur = &head;
    for(cur=cur->fd; cur!=&head; cur=cur->fd){
        eq = (struct executor_queue *)((unsigned long)cur - (unsigned long)&((struct executor_queue*)0)->list);
#ifdef DEBUG
        printf("found executor at: %p\n", eq);
#endif
        if (eq->executor_idx == idx){
            break;
        }
        eq = NULL;
    }
    if(eq != NULL){
#ifdef DEBUG
        printf("goint to remove pipeline %d\n",idx);
#endif  
        eq->ops->executor_free(eq);
        ppl_node_unlink(&eq->list);
        total_ppl-=1;
    }
    else{
        return -1;
    }
    return 0; 
}

int swap_a_patch(){
    struct patch_attr attr;
    unsigned int value_size;
    struct executor_queue * eq;
    unsigned int queue_type, idx_to_swap;
    unsigned char * value, * tmp_buffer;
    struct ppl_list_node * cur;
    int found_queue = 0;
    void *dst;
    if(!total_ppl){
        return -1;
    }
    read(0, &attr, sizeof(struct patch_attr));
    queue_type = attr.queue_type;
    idx_to_swap  = attr.idx_to_swap;
#ifdef DEBUG
    printf("type:%d\t idx to swap: %d\n", queue_type, idx_to_swap);
#endif
    
    cur = &head;
    for(cur=cur->fd; cur!=&head; cur=cur->fd)
    {
        eq = (struct executor_queue *)((unsigned long)cur - (unsigned long)&((struct executor_queue*)0)->list);
#ifdef DEBUG
        printf("found executor at: %p\n", eq);
#endif
        if(eq->queue_type == queue_type && eq->head > idx_to_swap && eq->tail<=idx_to_swap){
            found_queue = 1;
            break;
        }
    }
    if (!found_queue){
#ifdef DEBUG
        printf("executor not found for type %d\n", queue_type);
        printf("head: %d, tail: %d\n", eq->head, eq->tail);
#endif
        return -1;
    }
    value_size = eq->value_size;
    value = malloc(value_size);
#ifdef DEBUG
    puts("xD");
#endif
    // read new patch to buffer just allocated
    //read(0, value, value_size);
    safe_read(0, value, value_size);

    tmp_buffer = (char*)malloc(value_size);
    dst = &eq->elements[idx_to_swap * value_size];
    memcpy(tmp_buffer, dst, value_size);
    memcpy(dst, value, value_size);

    write(1, tmp_buffer, value_size);

    free(tmp_buffer);
    free(value);
    return 0;
}

int upload_patches(){
    struct patch_attr attr;
    unsigned int value_size, queue_type;
    struct executor_queue * eq;
    int found_queue = 0;
    unsigned char *value;
    struct ppl_list_node * cur;
    int ret=0;
    if(!total_ppl){
        return -1;
    }
    read(0, &attr, sizeof(struct patch_attr));
    queue_type = attr.queue_type; 

    // iterate over the linked list
    cur = &head;
    for(cur=cur->fd; cur!=&head; cur=cur->fd)
    {
        eq = (struct executor_queue *)((unsigned long)cur - (unsigned long)&((struct executor_queue*)0)->list);
#ifdef DEBUG
        printf("found executor at: %p\n", eq);
#endif
        if(eq->queue_type == queue_type){
            found_queue=1;
            break;
        }
    }

    if(!found_queue){
#ifdef DEBUG
        printf("executor not found for type %d\n", queue_type);
#endif
        return -1;
    }
    value_size = eq->value_size;
    value = malloc(value_size);
#ifdef DEBUG
    puts("p:");
#endif
    //read(0, value, value_size);
    safe_read(0, value, value_size);

    // invoke push_elem
    ret = eq->ops->push_elem(eq, value);

    free(value);
    return ret;
}

int run_patches(){
    struct patch_attr attr;
    struct ppl_list_node * cur;
    unsigned int queue_type;
    int found_queue = 0;
    int cur_run;
    unsigned int value_size;
    void* value;
    int ret;
    struct executor_queue* eq;
    if(!total_ppl){
        return -1;
    }
    read(0, &attr, sizeof(struct patch_attr));
    if(attr.queue_type > BRAINFUCK_EXECUTOR){
        return -1; 
    }
    queue_type = attr.queue_type;
    // iterate over the linked list
    cur = &head;
    for(cur=cur->fd; cur!=&head; cur=cur->fd)
    {
        eq = (struct executor_queue *)((unsigned long)cur - (unsigned long)&((struct executor_queue*)0)->list);
#ifdef DEBUG
        printf("%p\n", eq);
#endif
        if(eq->queue_type == queue_type && attr.number_of_patch <= eq->head - eq->tail){
            found_queue=1;
            break;
        }
    }
    if(!found_queue){
        puts("not found");
        return -1; 
    }
    value_size = eq->value_size;
    value = malloc(eq->value_size);
    memset(value, 0, value_size);
    for(cur_run=0; cur_run<attr.number_of_patch; cur_run++){
        // get_the element 
        eq->ops->get_elem(eq, value);
        ret=eq->ops->check_patch(eq, value);
        if(ret < 0){
            printf("%s... is not a valid patch\n", (char*)value);
            return 0;
        }
        eq->ops->run_patch(eq, value);
    }
    free(value);
    return 0;
}

#include "patch.c"
