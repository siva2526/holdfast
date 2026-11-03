#!/usr/bin/env python3
"""Stand-alone ransomware SIMULATOR for the Holdfast demo. It only touches files named doc*.txt in the current directory.
Usage (run INSIDE the mount, through a throw-away shell so the daemon never freezes your terminal):
    cd <mountpoint> && sh -c 'python3 /path/to/attacker.py inplace; true'
Modes: inplace | replace | perfile | benign-reencrypt | readenc (reads each file, encrypts it, writes it back in place: what real ransomware does)"""
import os, sys, time, hashlib
mode = sys.argv[1] if len(sys.argv) > 1 else 'inplace'
files = sorted(f for f in os.listdir('.') if f.startswith('doc') and f.endswith('.txt'))
print(f'[{mode}] {len(files)} target files', flush=True)
for f in files:
    n = os.path.getsize(f)
    if mode in ('inplace', 'benign-reencrypt'):
        fd = os.open(f, os.O_WRONLY); os.pwrite(fd, os.urandom(n), 0); os.close(fd)
    elif mode == 'readenc':
        d = open(f, 'rb').read(); k = os.urandom(16); ks = b''.join(hashlib.sha256(k + i.to_bytes(8, 'little')).digest() for i in range(len(d) // 32 + 1))
        fd = os.open(f, os.O_WRONLY); os.pwrite(fd, bytes(a ^ b for a, b in zip(d, ks)), 0); os.close(fd)
    elif mode == 'replace':
        open(f + '.tmp', 'wb').write(os.urandom(n)); os.rename(f + '.tmp', f)
    elif mode == 'perfile':
        pid = os.fork()
        if pid == 0:
            os.setsid()
            if os.fork() == 0:
                open(f + '.tmp', 'wb').write(os.urandom(n)); os.rename(f + '.tmp', f); os._exit(0)
            os._exit(0)
        os.waitpid(pid, 0)
    else: sys.exit('unknown mode')
    print('  encrypted', f, flush=True); time.sleep(0.15)
print('done', flush=True)
