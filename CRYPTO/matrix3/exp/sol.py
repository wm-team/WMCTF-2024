from sage.all import *
from tqdm import *
import hashlib
from Crypto.Cipher import AES
p = 2**302 + 307
k = 140
n = 10
alpha = 3
GFp = GF(p)
flagc = b'\x83\x1a)LB\xa6\xfb\xacS\xfa\xd03Q\x83c\xcd\xe6K\xbeI\xfc\x90_\xde=`nM&z\xca\x81\xcf\xdd\xde\x0c\x1b\xf8[C\xdc%\x97\xb2\xa4\xb4\xf6T'
Dlist = load("Dlist.sobj")

MD = Matrix(GFp , n**2 , k)
for i in tqdm(range(k)):
    for j in range(n**2):
        MD[j,i] = int(Dlist[i][j%n , j//n])

def right_kernel(M , q , bal = 1):
    M = Matrix(GF(q) , M)
    rows = M.nrows()
    cols = M.ncols()
    M0l , M0r = M[:,:rows] , M[:,rows:]
    M1 = -M0l.inverse() * M0r
    M1 = Matrix(ZZ , M1)
    if q == None:
        M = block_matrix([[M1.transpose() , identity_matrix(cols-rows)]])
    else:
        M = block_matrix([
            [identity_matrix(rows)*q , zero_matrix(rows , cols-rows)],
            [M1.transpose() , identity_matrix(cols-rows)]])
    M[-1 , -1] = bal
    return M.LLL()

res = right_kernel(MD , q=p)[:k-n**2]
v = vector(ZZ , res.nrows())
for i in range(res.nrows()):
    v[i] = 1 * sum([int(j) for j in res[i]])

res = res.transpose()
res = res.stack(v)
res = res.transpose()
res2 = right_kernel(res , q = p , bal = 1)
res2 = res2[:n**2+1]
res2 = res2.BKZ(block_size = 20)
res2 = res2.BKZ(block_size = 30)
res2 = res2.BKZ(block_size = 40)
shuffled_A = []
for i in range(res2.nrows()):
    last = res2[i , -1]
    if abs(last) != 1:
        continue
    templist = []
    for j in range(res2.ncols() - 1):
        temp = res2[i,j]*last + 1
        if temp < 0 or temp > alpha:
            print(i)
            break
        else:
            templist.append(temp)
    else:
        if templist.count(0) < n**2-1:
            shuffled_A.append(templist)
print(len(shuffled_A))

Ilist = [0]*100
for i in range(10):
    Ilist[i*10+i] = 1

Iv = vector(GFp , Ilist)
Ic = MD.solve_right(Iv)

tri_list = list(Matrix(GFp , shuffled_A)*Ic)
tri_pos = []
for i in range(100):
    if tri_list[i] == 1:
        tri_pos.append(i)



def pos_tag(i):
    targetv = [0]*100
    targetv[i] = 1
    targetv = vector(GFp , targetv)
    tempA = Matrix(GFp , shuffled_A)
    rm = tempA.solve_right(targetv)
    judge_vec = MD * rm
    row_tag = judge_vec[1]/judge_vec[0]
    assert row_tag == judge_vec[11]/judge_vec[10]
    col_tag = judge_vec[10]/judge_vec[0]
    assert col_tag == judge_vec[11]/judge_vec[1]
    row_mul = []
    for i in range(10):
        row_mul.append(judge_vec[i]/judge_vec[0])
    return row_tag , col_tag , row_mul

pos_table = [[0]*10 for _ in range(10)]
row_table = []

col_table = []
row_mul_table = []
for i in range(10):
    pos = tri_pos[i]
    row_tag, col_tag , row_mul = pos_tag(pos)
    row_table.append(row_tag)
    col_table.append(col_tag)
    pos_table[row_table.index(row_tag)][col_table.index(col_tag)] = i
    row_mul_table.append(row_mul)

for i in tqdm(range(100)):
    row_tag , col_tag , _ = pos_tag(i)
    pos_table[row_table.index(row_tag)][col_table.index(col_tag)] = i

rAlist = []
for x in range(128):
    recovered_A = Matrix(ZZ , 10)
    for i in range(10):
        for j in range(10):
            recovered_A[i,j] = shuffled_A[pos_table[i][j]][x]
    rAlist.append(recovered_A)

E1 = Matrix(GFp , 10)

tempM = Matrix(GFp , 10)
tempv = vector(GFp , 10)
print(row_mul_table[0])
for i in range(10):
    tempv[i] = (Dlist[i]*vector(GFp , row_mul_table[0]))[0]
    for j in range(10):
        tempM[j,i] = rAlist[i][j,0]
col0_mul = tempM.solve_left(tempv)      
print(tempv)  
print(col0_mul)
for i in range(10):
    for j in range(10):
        E1[j , i] = col0_mul[i] * row_mul_table[i][j]

print((E1**-1)*Dlist[0]*E1)
save(E1 , "E1.sobj")