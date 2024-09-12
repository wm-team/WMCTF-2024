import z3
import hashlib

with open("ciphertext.txt") as f:
    ct = f.read().strip()
import ast
ct = ast.literal_eval(ct)


with open("flag_hash.txt") as f:
    plaintext_hash = f.read().strip()
    plaintext_hash,salt  = plaintext_hash.split(":")

wheel_len = 64


solver = z3.Solver()

wheel = [z3.Int(f"wheel_{i}") for i in range(wheel_len)]

for i in range(wheel_len):
    solver.add(z3.And(wheel[i] >= 0, wheel[i] <= 1))

# define three state for wheel bits:
# 0: unknown
# -X: known to be state A for group X.
# X: known to be state B for group X.
# after iterating every groups, we will have multiple groups, then we do brute force to find the key.
ct_ptr = 0
wheel_ptr = -1
while ct_ptr < len(ct):
    distance = ct[ct_ptr]

    # for example, we have a number 7 at the first ciphertext,
    # then we can know the key is either 0000001 or 1111110.

    position = wheel_ptr + distance

    # handle looping of the wheel.
    position_real = position % wheel_len

    for i in range(position-1, wheel_ptr, -1):
        # handle looping
        i_real = i % wheel_len
        print(f"wheel[{position_real}] != wheel[{i}]")
        solver.add(wheel[position_real] != wheel[i_real])
    wheel_ptr = position_real
    ct_ptr += 1

# print(wheel)


from chal import K_Cessation as Homework,decode_ascii_with_random_msb

def try_decrypt(key):
    key = key
    h = Homework(key)
    flag0 = decode_ascii_with_random_msb(h.decrypt(ct))
    for flag in [flag0]:
        if hashlib.sha256((salt).encode() + flag).hexdigest() == plaintext_hash:
            print(key)
            print(flag)
            return True
    return False
count = 0
while solver.check() == z3.sat:
    count+=1
    m = solver.model()
    key = []
    for i in range(wheel_len):
        key.append(m[wheel[i]].as_long())
    if try_decrypt(key):
        print("found after",count,"tries")
        break
    block = []
    for d in m:
        c = d()
        block.append(c != m[d])
    solver.add(z3.Or(block))
else:
    print("not found after",count,"tries")
