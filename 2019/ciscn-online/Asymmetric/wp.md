首先，查看加密代码可以知道e的范围是1\~10,因此可以通过枚举获取e的值。其次，根据欧拉定理有：
$$
\forall\ x \in N_{p^{s}},\ x^{\phi\left( p^{s} \right)} = 1\ mod(p^{s})
$$
因此，我们只需要找到d使得：
$$
\text{ed} = 1\ mod\left( \phi(x) \right)
$$
直接求逆就可以得到d了，最后用d解密：
$$
\text{enc}^{d} = plain^{\text{de}} = plain\ mod\left( p^{s} \right)
$$
解密可以得到flag为：flag{ec33f669d2d659e2bc27dbffdfeb0f38}

```python
from problem import pubkey,encrypt 
from gmpy2 import *
import base64
import libnum

def root(n,i):
	l,r = 2,n
	while l<=r:
		mid = (l+r)/2
		if mid**i == n:
			return mid
		if mid**i>n:
			r = mid-1
		else:
			l = mid+1
	return -1

e,n = pubkey
for i in range(3,11):
	if root(n,i)!=-1 and libnum. prime_test(root(n,i)):
		s = i
		p = root(n,i)
		break

print s,p
d = invert(e,p**(s-1)*(p-1))
assert(p**s==n)
enc =encrypt
enc = base64.b64decode(enc)
enc = libnum.s2n(enc)
plain = pow(enc,d,p**s)
print libnum.n2s(plain)

```

