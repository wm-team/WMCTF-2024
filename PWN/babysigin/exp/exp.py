from pwn import*
import base64
p = remote(sys.argv[1],sys.argv[2])
with open("./test.ll","rb+") as f:
    content = f.read()
    f.close()
content = base64.b64encode(content)
p.recv()
p.sendline(content)
p.interactive()