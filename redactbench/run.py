import json
import re

from . import detect, gen


def norm(s):
    return re.sub(r"[^A-Za-z0-9]", "", s)


def score(seeds, held):
    out = {}
    for name, fn in detect.METHODS.items():
        leaked = total = false_red = looks_n = 0
        by_kind = {}
        for s in seeds:
            ses = gen.make_session(s, held)
            red = "\n".join(fn(e) for e in ses["events"])
            flat = norm(red)
            for kind, val in ses["secrets"]:
                core = norm(val)
                leak = core[:8] in flat or core[-8:] in flat
                total += 1
                leaked += leak
                k = by_kind.setdefault(kind, [0, 0])
                k[0] += 1
                k[1] += leak
            for v in ses["looks"]:
                looks_n += 1
                false_red += norm(v) not in flat
        out[name] = {"secrets_leaked": f"{leaked}/{total}", "leak_pct": round(100 * leaked / total, 1), "lookalikes_wrongly_removed": f"{false_red}/{looks_n}",
                     "leaks_by_type": {k: f"{v[1]}/{v[0]}" for k, v in sorted(by_kind.items()) if v[1]}}
    return out


def main():
    res = {"dev": score(range(0, 200), False), "held_out": score(range(1000, 1300), True)}
    json.dump(res, open("out/result.json", "w"), indent=1)
    for k, v in res.items():
        print(k)
        for m, d in v.items():
            print("  ", m, d)


if __name__ == "__main__":
    main()
