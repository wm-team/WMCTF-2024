from sage.all import *
E1 = load("E1.sobj")
from pwn import *

n= 10
def Matrix2str(M):
    alist = [M[i , j] for i in range(n) for j in range(n)]
    return ' '.join([str(i) for i in alist]).encode()

io = remote("0.0.0.0" , "10002")




payload = Matrix2str(E1)
print(payload)
io.recvuntil(b"give me E")
io.sendline(payload)
io.interactive()