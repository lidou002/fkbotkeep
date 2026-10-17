#!/usr/bin/env python3
# 用 node_proxy.py 把 NODE_LINK 转成本地 http 代理，sing-box 后台常驻到 job 结束，
# 并把 LOCAL_PROXY / PROXY_IP 写进 GITHUB_ENV 供后续步骤使用。
#
# 证书策略：先按链接里的设置连；连不上（hy2/tuic 自签、证书链异常很常见）
# 自动强制 insecure=true 再试一次。也可用 NODE_INSECURE=1 直接跳过校验。
import contextlib, io, json, os, re, socket, subprocess, sys, time
sys.path.insert(0, os.path.dirname(__file__))
import node_proxy as np

link = os.environ.get("NODE_LINK", "").strip()
if not link:
    print("未配置 NODE_LINK，直连")
    sys.exit(0)

workdir = os.environ.get("RUNNER_TEMP", "/tmp")
def fail(msg):
    sys.exit(redact(msg))

SENSITIVE = []
def redact(text):
    """公开仓库日志脱敏：去掉节点地址/SNI/UUID/密码，IP 只留前两段，域名全部打码。"""
    text = str(text or "")
    for v in sorted(SENSITIVE, key=len, reverse=True):
        text = text.replace(v, "***")
    text = re.sub(r"\b(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}\b", r"\1.*.*", text)
    text = re.sub(r"\[?[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}\]?", "[ipv6]", text)
    text = re.sub(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", "***", text)
    return text

try:
    with contextlib.redirect_stdout(io.StringIO()):  # 公开仓库：不打印节点域名/SNI
        scheme, info = np.normalize_link(link)
except Exception as e:
    fail("节点链接解析失败：%s" % e)
for v in info.values():  # 节点里所有字符串字段都视为敏感（host/sni/uuid/password/path/公钥…）
    if isinstance(v, str) and len(v) >= 4 and v.lower() not in (scheme, "tcp", "tls", "none", "auto"):
        SENSITIVE.append(v)
        print("::add-mask::%s" % v)  # 让 GitHub 在后续所有步骤日志里也自动打码
print("节点协议：%s" % scheme)

bindir = os.path.expanduser("~/.cache/sing-box-%s" % np.SING_BOX_VERSION)  # 由 actions/cache 缓存
os.makedirs(bindir, exist_ok=True)
binpath = np.ensure_singbox(bindir)
logpath = os.path.join(workdir, "sing-box.log")


def launch(force_insecure):
    """按指定证书策略启动 sing-box，成功返回 (proc, port, 出口IP)。"""
    ob = np.build_outbound(scheme, info, force_insecure=force_insecure)
    port = np._free_port()
    cfg = {"log": {"level": "warning"},
           "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": port}],
           "outbounds": [ob], "route": {"final": "proxy"}}
    cfgpath = os.path.join(workdir, "sb-config.json")
    fd = os.open(cfgpath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f)
    r = subprocess.run([binpath, "check", "-c", cfgpath], capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError("sing-box 配置校验失败：%s" % (r.stderr or r.stdout)[:300])
    proc = subprocess.Popen([binpath, "run", "-c", cfgpath], stdout=open(logpath, "w"),
                            stderr=subprocess.STDOUT, start_new_session=True)
    for _ in range(30):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=2).close()
            break
        except OSError:
            if proc.poll() is not None:
                raise RuntimeError("sing-box 启动后异常退出：%s" % np._read_log_tail(logpath))
            time.sleep(1)
    else:
        try:
            proc.terminate()
        except Exception:
            pass
        raise RuntimeError("sing-box 30s 内未就绪")
    ip = np.probe_exit_ip("http://127.0.0.1:%d" % port)
    if not ip:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            pass
        raise RuntimeError("代理自检失败：%s" % np._read_log_tail(logpath))
    return proc, port, ip


force_env = os.environ.get("NODE_INSECURE", "").strip().lower() in np._TRUTHY
attempts = [True] if force_env else [False, True]
last = None
proc = port = ip = None
used_force = False
for idx, force in enumerate(attempts, 1):
    try:
        proc, port, ip = launch(force)
        used_force = force
        break
    except Exception as e:
        last = e
        print("第 %d 次启动失败（insecure=%s）：%s" % (idx, force, redact(str(e))))
        if idx < len(attempts):
            print("改用「跳过证书验证」重试…")
else:
    fail("代理启动失败：%s" % last)

print("代理就绪，出口 IP：%s%s" % (ip, "（已跳过证书校验）" if used_force else ""))
with open(os.environ["GITHUB_ENV"], "a") as f:
    f.write("LOCAL_PROXY=http://127.0.0.1:%d\nPROXY_IP=%s\n" % (port, ip))
