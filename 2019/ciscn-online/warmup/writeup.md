aes是64位为一组，CTR是流密码，因此可以暴力破解

```
from pwn import *

debug=1

#context.log_level='debug'

p=remote('',12345)
charset ='{}_-'+ string.ascii_letters + string.digits + string.punctuation
pad = lambda s: s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)

def sl(x):
    p.sendline(x)


def cr(idx):
    ru('plaintext>')
    s = ''
    for q in range(8):
        for i in charset:
            sl('a'*8+i*idx)
            ru('result>')
            data = ru('\n')[:-1]
            t = data[idx*2+q*2:idx*2+2+q*2]
            ru('plaintext>')
            sl('a'*8)
            ru('result>')
            data = ru('\n')[:-1]
            w = data[idx*2+q*2:idx*2+2+q*2]
            if t == w:
                s += i
                print(i)
                break
    return s

flag = ''
for i in range(40,64,8):
    flag += cr(i)
    print(flag)
print(flag)
p.interactive()
```