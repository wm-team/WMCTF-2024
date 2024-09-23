from PIL import Image
import numpy as np
from Crypto.Util.number import *
import matplotlib.pyplot as plt
import pywt
import cv2

p = Image.open('flag.png').convert('RGB')
p_data = np.array(p)
R = p_data[:,:,0]
G = p_data[:,:,1].astype(np.float32)
B = p_data[:,:,2].astype(np.float32)

def string_to_bits(s):
    return bin(bytes_to_long(s.encode('utf-8')))[2:].zfill(8 * ((len(s) * 8 + 7) // 8))

def bits_to_string(b):
    n = int(b, 2)
    return long_to_bytes(n).decode('utf-8', 'ignore')

data = R.reshape(-1)%2
print(long_to_bytes(int(''.join([str(i) for i in data]),2)).replace(b'\x00',b''))

def extract_qim(block, delta):
    block_flat = block.flatten()
    avg = np.mean(block_flat)
    mod_value = avg % delta
    if mod_value < delta / 4 or mod_value > 3 * delta / 4:
        return '0'
    else:
        return '1'
    
def extract_watermark1(G_watermarked, watermark_length, delta=64):
    watermark_bits = []
    block_size = 8
    k = 0
    for i in range(0, G_watermarked.shape[0], block_size):
        for j in range(0, G_watermarked.shape[1], block_size):
            if k < watermark_length * 8:
                block = G_watermarked[i:i+block_size, j:j+block_size]
                if block.shape != (block_size, block_size):
                    continue
                coeffs = pywt.dwt2(block, 'haar')
                LL, (LH, HL, HH) = coeffs
                bit = extract_qim(LL, delta)
                watermark_bits.append(bit)
                k += 1

    # 将比特序列转换为字符串
    watermark_str = bits_to_string(''.join(watermark_bits))
    return watermark_str

print(extract_watermark1(G,253,8))

def dct2(block):
    return cv2.dct(block.astype(np.float32))

def idct2(block):
    return cv2.idct(block.astype(np.float32))

def svd2(matrix):
    U, S, V = np.linalg.svd(matrix, full_matrices=True)
    return U, S, V

def inverse_svd2(U, S, V):
    return np.dot(U, np.dot(np.diag(S), V))

def extract_watermark2(B_watermarked, B, watermark_length):
    h, w = B_watermarked.shape
    watermark_bits_extracted = []
    
    bit_index = 0
    
    for i in range(0, h, 8):
        for j in range(0, w, 8):
            if bit_index >= watermark_length * 8:
                break
                
            block_wm = B_watermarked[i:i+8, j:j+8]
            block_orig = B[i:i+8, j:j+8]
            
            dct_block_wm = dct2(block_wm)
            dct_block_orig = dct2(block_orig)
            
            U_wm, S_wm, V_wm = svd2(dct_block_wm)
            U_orig, S_orig, V_orig = svd2(dct_block_orig)
            
            delta_S = S_wm[0] - S_orig[0]
            
            if delta_S == 0:
                watermark_bits_extracted.append('1')
            else:
                watermark_bits_extracted.append('0')
            
            bit_index += 1
    
    watermark_bits_extracted = ''.join(watermark_bits_extracted)
    return bits_to_string(watermark_bits_extracted)

B_ori = np.array(Image.open('B.png').convert('L'))
print(extract_watermark2(B, B_ori, 83))