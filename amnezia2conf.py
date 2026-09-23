#!/usr/bin/env python3
"""
Конвертирует ключ AmneziaVPN (vpn://...) в .conf файл WireGuard / AmneziaWG,
пригодный для импорта в Keenetic / Netcraze.

Использование:
    python amnezia2conf.py client.vpn -o client.conf
    python amnezia2conf.py client.vpn --dump-json    # показать расшифрованный JSON
"""
import argparse
import base64
import json
import re
import sys
import zlib


def decode_vpn(text: str) -> dict:
    s = re.sub(r"\s+", "", text)
    if s.startswith("vpn://"):
        s = s[len("vpn://"):]
    s += "=" * (-len(s) % 4)
    raw = base64.urlsafe_b64decode(s)

    # Qt qCompress: 4 байта длины + zlib; иногда просто zlib; иногда без сжатия
    for unpack in (lambda b: zlib.decompress(b[4:]), zlib.decompress, lambda b: b):
        try:
            return json.loads(unpack(raw).decode("utf-8"))
        except Exception:
            continue
    raise ValueError("Не удалось расшифровать ключ: это не похоже на vpn:// от Amnezia")


def find_wg_container(data: dict):
    for c in data.get("containers", []):
        for key in ("awg", "wireguard"):
            if key in c:
                return key, c[key]
    raise ValueError("В ключе нет контейнера AmneziaWG/WireGuard "
                     "(возможно, это OpenVPN/XRay/Cloak — их Keenetic так не импортирует)")


def build_conf(data: dict) -> str:
    kind, cont = find_wg_container(data)
    last = cont.get("last_config", {})
    if isinstance(last, str):
        last = json.loads(last)

    dns1 = data.get("dns1") or "1.1.1.1"
    dns2 = data.get("dns2") or "1.0.0.1"

    conf = last.get("config")
    if conf:
        repl = {
            "$PRIMARY_DNS": dns1,
            "$SECONDARY_DNS": dns2,
            "$WIREGUARD_CLIENT_PRIVATE_KEY": last.get("client_priv_key", ""),
            "$WIREGUARD_CLIENT_IP": last.get("client_ip", ""),
            "$WIREGUARD_SERVER_PUBLIC_KEY": last.get("server_pub_key", ""),
            "$WIREGUARD_PSK": last.get("psk_key", ""),
            "$SERVER_IP_ADDRESS": last.get("hostName", data.get("hostName", "")),
        }
        for k, v in repl.items():
            conf = conf.replace(k, str(v))
    else:
        # Собираем вручную из полей, если готового текста нет
        lines = ["[Interface]",
                 f"Address = {last['client_ip']}/32",
                 f"DNS = {dns1}, {dns2}",
                 f"PrivateKey = {last['client_priv_key']}"]
        for p in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"):
            if p in last:
                lines.append(f"{p} = {last[p]}")
        lines += ["", "[Peer]", f"PublicKey = {last['server_pub_key']}"]
        if last.get("psk_key"):
            lines.append(f"PresharedKey = {last['psk_key']}")
        lines += ["AllowedIPs = 0.0.0.0/0, ::/0",
                  f"Endpoint = {last.get('hostName', data.get('hostName'))}:{last.get('port', cont.get('port'))}",
                  "PersistentKeepalive = 25"]
        conf = "\n".join(lines)

    conf = conf.replace("\r", "").strip() + "\n"

    # Предупреждения
    left = sorted(set(re.findall(r"\$[A-Z_]+", conf)))
    if left:
        print(f"ВНИМАНИЕ: не заменены плейсхолдеры: {', '.join(left)}", file=sys.stderr)
    if re.search(r"^\s*I[1-5]\s*=", conf, re.M) or re.search(r"^\s*H[1-4]\s*=\s*\d+-\d+", conf, re.M):
        print("ВНИМАНИЕ: в конфиге параметры AmneziaWG 1.5/2.0 (I1–I5 или диапазоны H). "
              "Роутер может их не поддерживать.", file=sys.stderr)
    if kind == "awg":
        print("Это AmneziaWG: на роутере нужна прошивка с поддержкой обфускации (Jc/Jmin/Jmax/S1/S2/H1–H4).",
              file=sys.stderr)
    return conf


def main():
    ap = argparse.ArgumentParser(description="Amnezia vpn:// -> WireGuard .conf")
    ap.add_argument("input", help="файл с ключом vpn://... (или '-' для stdin)")
    ap.add_argument("-o", "--output", help="куда сохранить .conf (по умолчанию — вывод в консоль)")
    ap.add_argument("--dump-json", action="store_true", help="вывести расшифрованный JSON и выйти")
    args = ap.parse_args()

    text = sys.stdin.read() if args.input == "-" else open(args.input, encoding="utf-8").read()
    data = decode_vpn(text)

    if args.dump_json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return

    conf = build_conf(data)
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as f:
            f.write(conf)
        print(f"Готово: {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(conf)


if __name__ == "__main__":
    main()
