from sage.all import *
import socketserver
from flag import flag
p = 2**302 + 307
k = 140
n = 10
alpha = 3

def Matrix2str(M):
    alist = [M[i , j] for i in range(n) for j in range(n)]
    return ' '.join([str(i) for i in alist]).encode()

def str2Matrix(s):
    Mlist = [int(i) for i in s.split(b' ')]
    print(Mlist)
    M = Matrix(GF(p) , n)
    for i in range(n):
        for j in range(n):
            M[i,j] = Mlist[i*n+j]
    return M
def check_M(M):
    for i in range(n):
        for j in range(n):
            if M[i,j] < 0 or M[i,j] >= alpha:
                return 0
    return 1
class server(socketserver.BaseRequestHandler):

    def _recv(self):
        data = self.request.recv(20480)
        return data.strip()

    def _send(self, msg, newline=True):
        if isinstance(msg , bytes):
            msg += b'\n'
        else:
            msg += '\n'
            msg = msg.encode()
        self.request.sendall(msg)

    def handle(self):
        Dlist = load("./Matrix3/Dlist.sobj")
        self._send(b"please give me E")
        Estr = self._recv()
        E = str2Matrix(Estr)
        print(E)
        E_1 = E**-1
        for i in range(k):
            if check_M(E_1*Dlist[i]*E) == 0:
                self._send(b"your private key is wrong")
                return 0
        self._send(b"your flag is")
        self._send(flag)
        return 0

    def finish(self):
        self.request.close()

class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10001
    server = ForkedServer((HOST, PORT), server)
    server.allow_reuse_address = True
    server.serve_forever()
 
