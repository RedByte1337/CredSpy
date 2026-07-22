#!/usr/bin/env python3
"""CredSpy — Entra ID user enumeration and auth method discovery via the public GetCredentialType API."""

import argparse
import csv
import re
import sys
import warnings
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
import urllib3

__version__ = "1.0.0"

CLIENT_ID = "4765445b-32c6-49b0-83e6-1d93765276ca"
AUTHORIZE_URL = (
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    f"?client_id={CLIENT_ID}&response_type=code"
    "&redirect_uri=https%3A%2F%2Fwww.office.com%2Flandingv2"
    "&response_mode=form_post"
    "&scope=openid%20profile%20https%3A%2F%2Fwww.office.com%2Fv2%2FOfficeHome.All"
    "&state=1&prompt=none"
)
GET_CREDENTIAL_URL = "https://login.microsoftonline.com/common/GetCredentialType"

IF_EXISTS = {
    -1: "Unknown", 0: "Exists", 1: "NotExist", 2: "Throttled", 4: "Error",
    5: "ExistsInOtherMicrosoftIDP", 6: "ExistsBothIDPs", 8: "ExistsInAcma",
}

# Codes the JS signin client treats as a valid: 
# > Exists/ExistsBothIDPs/ExistsInOtherMicrosoftIDP/ExistsInAcma
EXISTS_CODES = frozenset({0, 5, 6, 8})
DOMAIN_TYPE = {1: "Unknown", 2: "Consumer", 3: "Managed", 4: "Federated", 5: "CloudFederated"}
THROTTLE_STATUS = {0: "NotThrottled", 1: "AadThrottled", 2: "MsaThrottled"}
CREDENTIAL_TYPE = {
    0: "None", 1: "Password", 2: "RemoteNGC", 3: "OneTimeCode", 4: "Federation",
    5: "CloudFederation", 6: "OtherMicrosoftIdpFederation", 7: "Fido", 8: "GitHub",
    9: "PublicIdentifierCode", 10: "LinkedIn", 11: "RemoteLogin", 12: "Google",
    13: "AccessPass", 14: "Facebook", 15: "Certificate", 16: "OfflineAccount",
    18: "QrCodePin", 1000: "NoPreferredCredential",
}
REMOTE_NGC_TYPE = {1: "PushNotification", 3: "ListSessions"}

# field name -> display label (order used for Supported output and summary)
SUPPORTED = (
    ("password", "Password"),
    ("remote_ngc", "RemoteNGC"),
    ("fido", "Fido"),
    ("certificate", "Certificate"),
)

SCTX_RE = re.compile(r'"sCtx":"([^"]+)"')
LEGACY_CTX_RE = re.compile(r"reprocess\?ctx=([a-zA-Z0-9_\-]+)")
ANSI_RE = re.compile(r"\033\[[0-9;]*m")
EMAIL_PAD_MAX = 50
PREF_COL_WIDTH = len("Preferred: ") + max(len(f"{n} ({k})") for k, n in CREDENTIAL_TYPE.items())
CSV_HEADER = ["Email", "Exists", "PreferredType", "HasPassword", "RemoteNGC", "HasFido", "HasCertAuth", "DomainType"]

G, R, Y, O, _ = "\033[92m", "\033[91m", "\033[93m", "\033[38;5;208m", "\033[0m"


@dataclass
class Supported:
    password: bool = False
    remote_ngc: str | bool = False  # False | True | "PushNotification" | ...
    fido: int = 0
    certificate: bool = False


@dataclass
class Result:
    display: str
    if_exists: int
    throttle: int
    pref: Any
    domain: Any
    supported: Supported

    @property
    def exists(self) -> bool:
        """True for all IfExistsResult values the ESTS client treats as a real account."""
        return self.if_exists in EXISTS_CODES


def cv(text: str, code: str | None, on: bool) -> str:
    return f"{code}{text}{_}" if on and code else text


def pad(text: str, width: int) -> str:
    return text + " " * max(0, width - len(ANSI_RE.sub("", text)))


def enum_name(value: Any, mapping: dict[int, str]) -> str:
    return "n/a" if value is None else mapping.get(value, str(value))


def enum_label(value: Any, mapping: dict[int, str]) -> str:
    name = enum_name(value, mapping)
    return name if name == "n/a" or name == str(value) else f"{name} ({value})"


def cred_flag(creds: dict, bool_key: str, params_key: str) -> bool:
    if bool_key in creds and isinstance(creds[bool_key], bool):
        return creds[bool_key]
    return bool(creds.get(params_key))


def parse(data: dict, email: str) -> Result:
    creds = data.get("Credentials") or {}
    ests = data.get("EstsProperties") or {}
    ngc, fido = creds.get("RemoteNgcParams") or {}, creds.get("FidoParams") or {}

    remote_ngc: str | bool = False
    if cred_flag(creds, "HasRemoteNGC", "RemoteNgcParams"):
        ngc_type = ngc.get("DefaultType")
        remote_ngc = enum_name(ngc_type, REMOTE_NGC_TYPE) if ngc_type is not None else True

    return Result(
        display=data.get("Display", email),
        if_exists=data.get("IfExistsResult", 0),
        throttle=data.get("ThrottleStatus", 0),
        pref=creds.get("PrefCredential"),
        domain=ests.get("DomainType"),
        supported=Supported(
            password=bool(creds.get("HasPassword")),
            remote_ngc=remote_ngc,
            fido=len(fido.get("AllowList") or []) if cred_flag(creds, "HasFido", "FidoParams") else 0,
            certificate=cred_flag(creds, "HasCertAuth", "CertAuthParams"),
        ),
    )


def supported_active(s: Supported, field: str) -> bool:
    val = getattr(s, field)
    return bool(val) if field != "fido" else val > 0


def fmt_supported_item(field: str, label: str, s: Supported, *, color_on: bool) -> str:
    val = getattr(s, field)
    if field == "password":
        return label
    if field == "remote_ngc":
        text = f"{label} ({val})" if isinstance(val, str) else label
    elif field == "fido":
        text = f"{label} (Count: {val})"
    else:
        text = label
    return cv(text, O, color_on)


def build_supported(s: Supported, *, color_on: bool) -> str:
    items = [
        fmt_supported_item(f, lbl, s, color_on=color_on)
        for f, lbl in SUPPORTED
        if supported_active(s, f)
    ]
    return ", ".join(items) if items else "none"


def pref_color(pref: Any) -> str | None:
    if pref == 1:
        return G
    if pref in (7, 15):
        return R
    if pref == 2:
        return O
    return Y if pref is not None else None


def format_line(r: Result, *, color_on: bool, email_width: int) -> str:
    throttled = r.throttle not in (None, 0)
    ok = r.exists and not throttled
    use_color = color_on and ok
    display = pad(r.display, email_width)

    if not r.exists:
        line = f"{display} | IfExistsResult: {enum_label(r.if_exists, IF_EXISTS)}"
    else:
        pref_col = pad(
            f"Preferred: {cv(enum_label(r.pref, CREDENTIAL_TYPE), pref_color(r.pref), use_color)}",
            PREF_COL_WIDTH,
        )
        line = f"{display} | {pref_col} | Supported: {build_supported(r.supported, color_on=use_color)}"
        if r.domain is not None and r.domain != 3:
            line += f" | DomainType: {cv(enum_name(r.domain, DOMAIN_TYPE), R, use_color)}"

    if throttled:
        line += f" | ThrottleStatus: {enum_label(r.throttle, THROTTLE_STATUS)}"
    if not r.exists or throttled:
        return cv(line, R, color_on)
    return line


def to_csv_row(r: Result) -> list:
    s = r.supported
    return [
        r.display, enum_name(r.if_exists, IF_EXISTS), enum_name(r.pref, CREDENTIAL_TYPE),
        s.password, s.remote_ngc, s.fido > 0, s.certificate, enum_name(r.domain, DOMAIN_TYPE),
    ]


def record_stats(stats: dict, r: Result) -> None:
    stats["total"] += 1
    if r.throttle not in (None, 0):
        stats["throttled"] += 1
    if not r.exists:
        return
    stats["exists"] += 1
    stats["pref"][enum_name(r.pref, CREDENTIAL_TYPE)] += 1
    for field, label in SUPPORTED:
        if supported_active(r.supported, field):
            stats["supported"][label] += 1
    stats["domain"][enum_name(r.domain, DOMAIN_TYPE)] += 1


def print_summary(stats: dict) -> None:
    total, exists = stats["total"], stats["exists"]
    if not total:
        return
    print("\n--- Summary ---")
    print(f"Exists: {exists}/{total}")
    print(f"Throttled: {stats['throttled']}/{total}")
    if not exists:
        return
    print(f"Preferred: {', '.join(f'{k} {v}/{exists}' for k, v in stats['pref'].most_common())}")
    sup = ", ".join(f"{lbl} {stats['supported'][lbl]}/{exists}" for _, lbl in SUPPORTED)
    print(f"Supported: {sup}")
    print(f"DomainType: {', '.join(f'{k} {v}/{exists}' for k, v in stats['domain'].most_common())}")


def print_file_summary(counts: dict, paths: dict) -> None:
    labels = {
        "csv": "CSV",
        "existing": "save-existing",
        "ngc": "save-ngc",
        "password_preferred": "save-password-preferred",
    }
    lines = [f"{labels[k]} ({paths[k]}): {counts[k]} entries" for k in paths]
    if lines:
        print("\n--- Output files ---")
        print("\n".join(lines))


def confirm_overwrite(paths: list[str]) -> bool:
    existing = [p for p in paths if Path(p).exists()]
    if not existing:
        return True
    print("Output file(s) already exist:")
    for p in existing:
        print(f"  {p}")
    answer = input("Overwrite? [Y/n] ").strip().lower()
    return answer in ("", "y", "yes")


def write_saves(r: Result, saves: dict, counts: dict) -> None:
    line = r.display + "\n"
    if saves.get("existing") and r.exists:
        saves["existing"].write(line)
        counts["existing"] += 1
    if saves.get("ngc") and supported_active(r.supported, "remote_ngc"):
        saves["ngc"].write(line)
        counts["ngc"] += 1
    if saves.get("password_preferred") and r.exists and r.pref == 1:
        saves["password_preferred"].write(line)
        counts["password_preferred"] += 1


def load_emails(target: str) -> list[str]:
    path = Path(target)
    if path.is_file():
        emails = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()
                  if ln.strip() and not ln.strip().startswith("#")]
        if not emails:
            raise ValueError(f"No emails in {path}")
        return emails
    if "@" not in target:
        raise ValueError(f"'{target}' is not a file or email address")
    return [target]


def make_session(proxy: str | None) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
        s.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        warnings.filterwarnings("ignore", message="Failed to patch SSL settings for unverified requests")
    return s


def fetch_ctx(session: requests.Session) -> str | None:
    r = session.get(AUTHORIZE_URL, cookies={"AADSSO": "NA|NoExtension"}, allow_redirects=False, timeout=30)
    r.raise_for_status()
    body = r.text.replace("\\u0026", "&")
    for pattern in (SCTX_RE, LEGACY_CTX_RE):
        if m := pattern.search(body):
            return m.group(1)
    return None


def query(session: requests.Session, email: str, ctx: str | None, *, skip_ngc: bool = False) -> tuple[dict | None, int]:
    payload = {
        "username": email, "isOtherIdpSupported": True, "checkPhones": False,
        "isRemoteNGCSupported": not skip_ngc, "isCookieBannerShown": False, "isFidoSupported": True,
        "country": "US", "forceotclogin": False, "isExternalFederationDisallowed": False,
        "isRemoteConnectSupported": False, "federationFlags": 0, "isSignup": False,
        "isAccessPassSupported": True, "isQrCodePinSupported": True,
    }
    if ctx:
        payload["originalRequest"] = ctx
    r = session.post(
        f"{GET_CREDENTIAL_URL}?mkt=en-US", json=payload,
        headers={"Content-Type": "application/json", "Origin": "https://login.microsoftonline.com"},
        timeout=30,
    )
    if r.status_code != 200:
        return None, r.status_code
    return r.json(), 200


def main() -> int:
    # Parse arguments
    p = argparse.ArgumentParser(
        prog="credspy",
        description=(
            f"CredSpy v{__version__} - by RedByte1337\n"
            "Enumerate Microsoft Entra accounts and auth methods via GetCredentialType."
        ),
        epilog=f"For more information, see: https://github.com/RedByte1337/CredSpy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("target", help="Email address or text file (one per line)")
    p.add_argument("--proxy", help="Proxy URL; disables SSL verification (Format: 'http://127.0.0.1:8080')")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--csv", metavar="FILE", help="Write results to CSV")
    p.add_argument("--save-existing", metavar="FILE", help="Save emails which exist to file")
    p.add_argument("--save-ngc", metavar="FILE", help="Save emails with RemoteNGC support to file")
    p.add_argument("--save-password-preferred", metavar="FILE", help="Save emails with password as preferred method to file")
    p.add_argument("--skip-ngc", action="store_true", help="Disable RemoteNGC checks (avoids push notifications when RemoteNGC is preferred)")
    args = p.parse_args()
    color_on = not args.no_color and sys.stdout.isatty()

    # Load email list
    try:
        emails = load_emails(args.target)
    except (OSError, ValueError) as e:
        print(cv(f"[-] {e}", R, color_on), file=sys.stderr)
        return 1

    # Set up HTTP session and acquire Microsoft session context
    session = make_session(args.proxy)
    if args.proxy:
        print(f"[*] Proxy: {args.proxy} (verify=False)")

    try:
        ctx = fetch_ctx(session)
    except requests.RequestException as e:
        print(cv(f"[-] Failed to get session ctx: {e}", R, color_on), file=sys.stderr)
        return 1
    print(cv("[+] Session ctx acquired", G, color_on) if ctx else cv("[!] No ctx found, continuing anyway", Y, color_on))

    # Prepare output files
    email_width = min(max(len(e) for e in emails), EMAIL_PAD_MAX)
    stats = {"total": 0, "exists": 0, "throttled": 0, "pref": Counter(), "supported": Counter(), "domain": Counter()}
    save_opts = {
        "existing": args.save_existing,
        "ngc": args.save_ngc,
        "password_preferred": args.save_password_preferred,
    }
    out_paths = {k: p for k, p in {"csv": args.csv, **save_opts}.items() if p}
    if out_paths and not confirm_overwrite(list(out_paths.values())):
        return 1

    csv_f = open(args.csv, "w", newline="", encoding="utf-8") if args.csv else None
    writer = csv.writer(csv_f) if csv_f else None
    if writer:
        writer.writerow(CSV_HEADER)

    saves = {k: open(p, "w", encoding="utf-8") for k, p in save_opts.items() if p}
    out_counts = {k: 0 for k in out_paths}

    # Query each email and collect results
    for email in emails:
        try:
            data, status = query(session, email, ctx, skip_ngc=args.skip_ngc)
            if data is None:
                print(cv(f"[-] {email}: HTTP {status}", R, color_on), file=sys.stderr)
                continue
            result = parse(data, email)
            print(format_line(result, color_on=color_on, email_width=email_width))
            if writer:
                writer.writerow(to_csv_row(result))
                out_counts["csv"] += 1
            record_stats(stats, result)
            write_saves(result, saves, out_counts)
        except requests.RequestException as e:
            print(cv(f"[-] {email}: {e}", R, color_on), file=sys.stderr)

    # Print summary
    if csv_f:
        csv_f.close()
    for f in saves.values():
        f.close()
    print_summary(stats)
    print_file_summary(out_counts, out_paths)
    return 0


def cli() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    cli()
