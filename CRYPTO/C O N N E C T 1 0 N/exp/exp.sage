from Crypto.Util.number import *
from os import urandom
import random

f = open(r'output.txt','r')
data = eval(f.read())

for _ in range(4):
    M = matrix(128,128)
    v0 = zero_matrix(128)[0]
    
    M = matrix(128,128)
    for i in range(128):
        for j in range(128):
            temp = bin(data[_][i][j])[2:].zfill(128)
            m = [-1 if tt == '1' else 1 for tt in temp]
            for k in range(128):
                M[k,i] += m[k]
    
    T = block_matrix([
        [identity_matrix(128),M],
        [0,identity_matrix(128)*8]
    ])
    T[:,-128:] *= 2^10
    res = T.BKZ(block_size=30)
    
    for i in res:
        if(all(abs(j)==1 for j in i[:128])):
            ans1 = ""
            ans2 = ""
            for j in i[:128]:
                if j == -1:
                    ans1 += '1'
                    ans2 += '0'
                else:
                    ans1 += '0'
                    ans2 += '1'
            print(long_to_bytes(int(ans1,2)))
            print(long_to_bytes(int(ans2,2)))
