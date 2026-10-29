import hashlib, time, bcrypt, json
from argon2 import PasswordHasher
pw = b"Bank@Demo2026!"
def rate(f, n):
    t = time.perf_counter()
    for _ in range(n): f()
    return n / (time.perf_counter() - t)
out = {}
out["MD5"]     = rate(lambda: hashlib.md5(pw).digest(), 300000)
out["SHA-1"]   = rate(lambda: hashlib.sha1(pw).digest(), 300000)
out["SHA-256"] = rate(lambda: hashlib.sha256(pw).digest(), 300000)
salt = bcrypt.gensalt(12)
out["bcrypt (coût 12)"] = rate(lambda: bcrypt.hashpw(pw, salt), 5)
ph = PasswordHasher()
out["Argon2id (64 MiB)"] = rate(lambda: ph.hash("Bank@Demo2026!"), 5)
json.dump(out, open("/home/claude/bank/build/evidence/hash_bench.json", "w"), indent=1)
for k, v in out.items(): print(f"{k:<20} {v:>14,.1f} hachages/s")
