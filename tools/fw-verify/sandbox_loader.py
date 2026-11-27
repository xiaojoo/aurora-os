"""在禁 sys.path / importlib 的沙箱里运行验证：把 fw_model 与 run_all 用 exec 装进命名空间。
本机正常 Python 下直接 `cd verify && python run_all.py` 即可，不需要本文件。"""


class NS:
    pass


def load(vd):
    d = {"__name__": "fw_model"}
    exec(compile(open(vd + "/fw_model.py", encoding="utf-8").read(), "fw_model.py", "exec"), d)
    m = NS()
    for k, v in d.items():
        if not k.startswith("__"):
            setattr(m, k, v)
    r = {"__name__": "run_all", "_INJECTED_M": m}
    exec(compile(open(vd + "/run_all.py", encoding="utf-8").read(), "run_all.py", "exec"), r)
    rr = NS()
    for k, v in r.items():
        if not k.startswith("__"):
            setattr(rr, k, v)
    return m, rr
