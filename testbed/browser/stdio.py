import os, socket, sys, threading, time
# startup marker, never forwarded to TLS. 예비 중계는 여기서 기다리며, 입구가 꺼져 'G' 없이 입력이 닫히면 접속하지 않고 끝낸다.
if os.read(0,1)!=b"G":
    sys.exit(0)
# 출발지 IP는 이 중계가 붙은 시험 단말의 고정 IP만 허용한다(A .11 / B .12 / X .13). 목적지는 Caddy로 고정.
SOURCES={"172.28.10.11","172.28.10.12","172.28.10.13"}
source=sys.argv[1] if len(sys.argv)>1 else "172.28.10.11"
if source not in SOURCES:
    sys.stdout.buffer.write(b"E"); sys.stdout.buffer.flush(); sys.exit(1)
try:
    s=socket.create_connection(("172.28.20.5",8443),3,source_address=(source,0))
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
