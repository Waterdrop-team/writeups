用qira神器，跟着输入流走
然后走到0x4056ff，发现有一个xor，对应xor的是x
再跟踪了下，然后发现输入的密码与下面的字符串异或了一下
xyz{|}

应该就是密码了

用户名的话，首先是sms4加密，然后再用魔改的base64加密了

sms4的我是用c语言解的，这里就不放了，下面是解base64的

```

def decode(a1):
    b = 'IJLMNOPKABDEFGHCQRTUVWXSYZbcdefa45789+/6ghjklmnioprstuvqwxz0123y'
    d = []
    for i in range(0,len(a1),4):
        c = []
        for q in range(4):
            if a1[i+q] not in b:
                c.append(0)
            else:
                c.append(b.index(a1[i+q]))
        t1 = (c[0]<<2) | (c[1]>>4)
        t2 = ((c[1]&0xf)<<4) | (c[2]>>2)
        t3 = ((c[2]&0x3)<<6) | c[3]
        d += [t1,t2,t3]
    return d


t1 = 'RVYtG85NQ9OPHU4uQ8AuFM+MHVVrFMJMR8FuF8WJQ8Y='
#t1 = 'G9YuQtFtFVQrRM4uQ8AuR8IpGMNvFM9tG8FqQ8QwR9Q='
t2 = decode(t1)
s = ''
for i in range(32):
    s+=chr(t2[i])
t3 = []
for i in range(0,len(s),2):
    t3.append(int(s[i:i+2],16))
keys=[0xDA,0x98,0xF1,0xDA,0x31,0x2A,0xB7,0x53,0xA5,0x70,0x3A,0xB,0xFD,0x29,0xD,0xD6]
print(t3)

t4 = '6261647265723132'
s = ''
for i in range(0,len(t4),2):
    s += chr(int(t4[i:i+2],16))
print(s)
```
