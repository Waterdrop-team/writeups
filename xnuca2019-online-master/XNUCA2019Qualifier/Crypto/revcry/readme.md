01A-Za-z 一共54个字符，分成6组，每组9个字符。那么会有$C^{9}_{54}/6$种分法，但答案仅为其中一种，将答案排为升序后做了一种自定义的hash算法，最后进行hash比较，当恢复出来这种分法之后才能根据题目要求提交flag。

Go实现，有两个goruntine，其中一个用来显示动画，另外一个用来做运算，包括排序和计算hash。
