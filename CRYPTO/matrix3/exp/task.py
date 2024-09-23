from sage.all import *
import hashlib
from Crypto.Cipher import AES

p = 2**302 + 307
k = 140
n = 10
alpha = 3

GFp = GF(p)
def pad(m):
    return m + (16-(len(m)%16))*bytes([16-(len(m)%16)])
def keygen():
    E = random_matrix(GFp , n , n)
    while E.rank() != n:
        E = random_matrix(GFp , n , n)
    Alist = []

    for i in range(k):
        A = random_matrix(ZZ , n , n , x=0 , y = alpha)
        A = Matrix(GFp , A)
        while A.rank() != n:
            A = random_matrix(ZZ , n , n , x=0 , y = alpha)
            A = Matrix(GFp , A)
        Alist.append(A)
    E_1 = E**(-1)
    Dlist = []
    save(E , "E.sobj")
    for i in range(k):
        D = E * Alist[i] *E_1
        Dlist.append(D)
    return Alist , Dlist , E

Alist , Dlist , E= keygen()
save(Dlist ,"Dlist.sobj")
save(Alist , "Alist.sobj")
print(Alist[0])

#b'\x83\x1a)LB\xa6\xfb\xacS\xfa\xd03Q\x83c\xcd\xe6K\xbeI\xfc\x90_\xde=`nM&z\xca\x81\xcf\xdd\xde\x0c\x1b\xf8[C\xdc%\x97\xb2\xa4\xb4\xf6T'