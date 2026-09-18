import importlib.util, hashlib, hmac, time, sys
spec = importlib.util.spec_from_file_location("serverpy", "server.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

ts = int(time.time())
def sgn(master, page, t):
    key = hashlib.sha256(master.encode() + b"kl17").digest()[:32]
    return hmac.new(key, ("page=%d&ts=%d" % (page, t)).encode(), hashlib.sha256).hexdigest()

sg = sgn("Fatdog_reclaim", 1, ts)
sgD = sgn("Fatdog_reclaims", 1, ts)
print("real accept :", m._kl17_try("Fatdog_reclaim", 1, ts, sg))
print("decoy accept:", m._kl17_try("Fatdog_reclaim", 1, ts, sgD))
print("decoy own   :", m._kl17_try("Fatdog_reclaims", 1, ts, sgD))
print("bad sign    :", m._kl17_try("Fatdog_reclaim", 1, ts, "0" * 64))
print("wrong page  :", m._kl17_try("Fatdog_reclaim", 2, ts, sg))
print("stale ts    :", m._kl17_try("Fatdog_reclaim", 1, ts - 5000, sgn("Fatdog_reclaim", 1, ts - 5000)))
s = sum(m.NUMS_KL17)
print("sum         :", s)
print("SUM_HASH    :", hashlib.sha256(str(s).encode()).hexdigest())
print("route       :", any(r.path == "/api/kl17" for r in m.app.routes))
