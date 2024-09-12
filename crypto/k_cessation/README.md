### k_cessation

#### description

```
## Background:
K-Cessation cipher is a cipher that uses a K bit wheel to pick the next cipher bit from plaintext bit.
When encryption starts, the wheel starts at the last bit of the wheel.
The wheel loops around when it reaches the end.
For every plaintext bit, the wheel is rotated to the next bit in the wheel that matches the plaintext bit, and the distance rotated is appended to the ciphertext.

Therefore, if the wheel is not known, it is not possible to decrypt the ciphertext. 
Or is it?


## Example:
To encode "youtu.be/dQw4w9WgXcQ" in 64-Cessation with the wheel 1100011011100011100110100011110110010110010100001011111011111010:
1. convert the plaintext to bits: 01111001 01101111 01110101 01110100 01110101 00101110 01100010 01100101 00101111 01100100 01010001 01110111 00110100 01110111 00111001 01010111 01100111 01011000 01100011 01010001
2. from wheel[-1] to the next "0" bit in the wheel, distance is 3, the current wheel position is wheel[2]
3. from wheel[2] to the next "1" bit in the wheel, distance is 3, the current wheel position is wheel[5]
4. repeat the steps until all bits is encoded
5. the result is 3312121232111411211311221152515233123332223411313221112161142123243321244111111311111112111131113211132412111212112112321122115251142114213312132313311222111112


## Challenge:
A flag is encoded with 64-Cessation cipher. 
The wheel is not known except that it is 64 bits long. 
The ciphertext is given in ciphertext.txt.
The flag is only known to be an ASCII string that is longer than 64 characters. 
No part of the flag is known, which means the flag is NOT in WMCTF{} or FLAG{} format.
When submitting, please make the flag in WMCTF{} format.
Note that, The most significant bit of each ASCII byte is flipped with a random bit.
You need to extract the flag from the ciphertext and submit it.
For your convenience, a salted sha256 hash of the flag is given in flag_hash.txt.


Chinese：
## 背景：
K-Cessation 密码是一种使用 K 位轮从明文位中挑选下一个密码位的古典密码。
当加密开始时，从轮子的最后一位开始。
当轮子到达终点时，它会从头开始循环。
对于每个明文位，轮子会旋转到轮子中与明文位匹配的下一个位，并将旋转的距离附加到密文中。

因此，如果不知道轮子，就不可能解密密文。 
是这样吗？


## 例子：
要使用轮子 1100011011100011100110100011110110010110010100001011111011111010 将“youtu.be/dQw4w9WgXcQ”编码为 64-Cessation：
1. 将明文转换为比特： 01111001 01101111 01110101 01110100 01110101 00101110 01100010 01100101 00101111 01100100 01010001 01110111 0011 0100 01110111 00111001 01010111 01100111 01011000 01100011 01010001
2.从wheel[-1]到轮子中的下一个“0”位，距离为3，当前轮位置为wheel[2]
3.从wheel[2]到轮子中的下一个“1”位，距离为3，当前轮子位置为wheel[5]
4. 重复步骤直到所有位都被编码
5.结果为3312121232111411211311221152515233123332223411313221112161142123243321244111111311111112111131113211132412111212112112321122115251142114213312132313311222111112


## 挑战：
一个野生Flag使用 64-Cessation 密码进行编码。 
轮子内容是未知的，它是 64 位长。 
密文在 ciphertext.txt 中给出。
该Flag已知是长度超过 64 个字符的 ASCII 字符串。 
除此之外，该Flag的任何部分都是未知的，这意味着该Flag不是 WMCTF{} 或 FLAG{} 格式。
提交时，请将Flag改为WMCTF{}格式。
请注意，每个ASCII字节的最高有效位被随机翻转。
您需要从密文中提取Flag并提交。
为了您的方便，flag_hash.txt 中给出了该Flag的盐焗 SHA-256 哈希值。
```



#### writeup

1. 阅读题干或题目给出的代码，了解K-Cessation的加密方式。具体来说：
   - K-Cessation是一种古典密码，使用一个K位的轮子来选择下一个密文位。
   - 当加密开始时，轮子从轮子的最后一位开始。
   - 当轮子到达末尾时，它会循环。
   - 对于每个明文位，轮子被旋转到与明文位匹配的轮子中的下一个位，并且旋转的距离被附加到密文中。
   - 为了增加题目的难度，因为ASCII字符字节的最高位始终为0，这可能造成已知明文攻击，所以对每个字节的最高位进行了随机翻转。
   - 同样的，为了防止已知明文攻击，Flag不是WMCTF{}或FLAG{}格式。
2. 题目使用了64-Cessation，也就是说轮子有64位。

```
假设的轮子：（目前除了轮子长度是64外，没有其它可知信息）
????????????????????????????????????????????????????????????????
其中?的取值是0或1
```

3. 题目给出了加密后的密文，通过密文的第一个字符是2可知，轮子的第[1]与[2]位的取值是相反的。

```
假设的轮子：
aA??????????????????????????????????????????????????????????????
其中?的取值是0或1，每组字母的取值是0/1或1/0
```

4. 重复第三步得知，因为密文的第四个字符是3，所以轮子的第[5,6]与[7]位的取值是相反的。

```
假设的轮子：
aAbcddD?????????????????????????????????????????????????????????
其中?的取值是0或1，每组字母的取值是0/1或1/0
```

5. 继续重复步骤可以得到一系列约束，最终可以通过z3求解器得到轮子的可能取值。

```
all(wheel[x] in [0,1] for x in range(64))
wheel[1] != wheel[0]
wheel[6] != wheel[5]
wheel[6] != wheel[4]
wheel[11] != wheel[10]
wheel[11] != wheel[9]
wheel[13] != wheel[12]
wheel[18] != wheel[17]
wheel[18] != wheel[16]
wheel[18] != wheel[15]
wheel[21] != wheel[20]
wheel[24] != wheel[23]
wheel[24] != wheel[22]
wheel[29] != wheel[28]
wheel[33] != wheel[32]
wheel[35] != wheel[34]
wheel[37] != wheel[36]
wheel[41] != wheel[40]
wheel[41] != wheel[39]
wheel[48] != wheel[47]
wheel[48] != wheel[46]
wheel[48] != wheel[45]
wheel[48] != wheel[44]
wheel[48] != wheel[43]
wheel[54] != wheel[53]
wheel[54] != wheel[52]
...
```

6. 通过给出的Flag SHA256哈希值，可以验证轮子的取值是否正确。
7. 通过正确的轮子的取值，可以解密密文（将每个明文字节的最高位置0）得到Flag。
   Flag是`DoubleUmCtF[S33K1NG_tru7h-7h3_w1s3-f1nd_1n57e4d-17s_pr0f0und-4b5ence_n0w-g0_s0lv3-th3_3y3s-1n_N0ita]`，根据题干要求将格式转换为`WMCTF{S33K1NG_tru7h-7h3_w1s3-f1nd_1n57e4d-17s_pr0f0und-4b5ence_n0w-g0_s0lv3-th3_3y3s-1n_N0ita}`。