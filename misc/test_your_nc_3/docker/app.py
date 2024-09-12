#!/usr/bin/env python
from multiprocessing import Process, Queue
import subprocess
import os
import traceback
import sys
import signal

def drop_privileges():
    os.setgroups([])
    os.setgid(65534)
    os.setresuid(65534,65534,65534)
    os.setuid(65534)
    os.environ['HOME'] = '/nonexistent'

def sandbox_command(queue,command):
    drop_privileges()
    p = subprocess.Popen(command,shell=True)
    status_code = p.wait()
    queue.put(status_code)
    return

if __name__ == "__main__":
    signal.alarm(1<<14>>5<<1>>4)
    while 1:
        os.chmod("/flag",0)
        sys.stdout.write("nobody@test-your-nc-3:/$ ")
        command = sys.stdin.readline().strip()
        if command == "exit":
            break
        queue = Queue()
        p = Process(target=sandbox_command, args=(queue,command))
        p.start()
        status_code = queue.get(True)
        if status_code == 0:
            pass
        elif status_code == 143:
            print("Terminated")
        elif status_code == 137:
            print("Killed")
        elif status_code == 139:
            print("Segmentation fault")
        elif status_code == 134:
            print("Aborted")
        elif status_code == 132:
            print("Illegal instruction")
        elif status_code == 124:
            print("Alarm clock")

        p.terminate()
        queue.close()
