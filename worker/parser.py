import os, time, sys

print("[*] Worker daemon running. Listening for file processing tasks...", flush=True)

uid = os.getuid()
print(f"[*] Worker UID: {uid} (Root: {uid == 0})", flush=True)

while True:
    time.sleep(10)
