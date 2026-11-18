import os, socket, sys, threading, time
os.read(0,1)  # startup marker, never forwarded to TLS
try:
    s=socket.create_connection(("172.28.20.5",8443),3,source_address=("172.28.10.11",0))
except OSError:
    sys.stdout.buffer.write(b"E"); sys.stdout.buffer.flush(); sys.exit(1)
sys.stdout.buffer.write(b"R"); sys.stdout.buffer.flush()
def upload():
    try:
        while True:
            data=os.read(0,65536)
            if not data: break
            s.sendall(data)
    except OSError: pass
    finally:
        try:s.shutdown(socket.SHUT_WR)
        except OSError:pass
threading.Thread(target=upload,daemon=True).start()
s.settimeout(1)
end=time.monotonic()+90
try:
    while time.monotonic()<end:
        try:data=s.recv(65536)
        except socket.timeout:continue
        if not data:break
        sys.stdout.buffer.write(data); sys.stdout.buffer.flush()
except (OSError,BrokenPipeError):pass
finally:s.close()
