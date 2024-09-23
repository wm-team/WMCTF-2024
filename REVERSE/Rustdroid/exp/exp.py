def single_byte_encrypt(x):
    result = x
    result = (result >> 1) | ((result << 7) & 0xff)
    result ^= 0xef
    result = (result >> 2) | ((result << 6) & 0xff)
    result ^= 0xbe
    result = (result >> 3) | (result << 5 & 0xff)
    result ^= 0xad
    result = (result >> 4) | (result << 4 & 0xff)
    result ^= 0xde
    result = (result >> 5) | (result << 3 & 0xff)
    return result

encode=[ 0x1F, 0xBA, 0x15, 0x42, 0x59, 0xCE, 0x4F, 0x4E, 0x94,0xD9, 0xBF, 0x69, 0xAE, 0x5B, 0x74, 0xC, 0xC0, 0xFC,0x8A, 0x7F, 0x9C, 0x1E, 8, 0x87, 0xF5, 0x6B, 0x64,0xF5, 0x87, 0x8F, 0xB0, 0x2B, 0xE2, 0x53, 0xFF, 0x29]
key = [  0x66, 0x75, 0x6E, 0x40, 0x65, 0x5A]
xor_table =[0x77, 0x88, 0x99, 0x66]
def rc4(key, data):
    key_length = len(key)
    s = list(range(256))  
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % key_length]) % 256  
        s[i], s[j] = s[j], s[i]  

    out = []
    i = j = 0
    index =0
    for y in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i] 
        k = s[(s[i] + s[j]) % 256]
        out.append(y ^ k ^xor_table[index%4]) 
        index+=1
    return out

decrypted_data = rc4(key, encode)
print(decrypted_data)
print("WMCTF{",end="")
for i in range(0,36):
    for j in range(30,128):
        x = single_byte_encrypt(j)
        if x== decrypted_data[i]:
            print(chr(j),end="")
            break
print("}",end="")