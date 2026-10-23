#!/usr/bin/env python3
"""
config.py — API key & settings manager for php2shell-scanner / dork.py

Keys are stored at  ~/.php2shell/config.json  (created automatically).
A local override file  ./config.local.json  is merged on top and lets you
keep project-specific keys outside your home directory — add it to .gitignore!

Priority chain (highest wins):
  1. Environment variable
  2. Local file  ./config.local.json
  3. User file   ~/.php2shell/config.json
  4. Built-in default

Usage (CLI)
-----------
  python config.py --set shodan_api_key=sk-xxxxx
  python config.py --set censys_api_id=ID censys_api_secret=SECRET
  python config.py --set fofa_email=you@mail.com fofa_key=xxxxx
  python config.py --set default_max_per_dork=200
  python config.py --show
  python config.py --show --reveal
  python config.py --delete bing_api_key
  python config.py --test shodan
  python config.py --test all
  python config.py --reset

Import API (used by dork.py)
-----------------------------
  from config import load_config

  cfg = load_config()
  key = cfg.get("shodan_api_key")        # "" if not set
  n   = cfg.setting("default_max_per_dork")  # typed, with default
"""

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

CONFIG_VERSION = "1"
CONFIG_DIR  = Path.home() / ".php2shell"
CONFIG_FILE = CONFIG_DIR  / "config.json"
LOCAL_FILE  = Path("config.local.json")   # project-level override

# Credential keys  →  human description
CRED_KEYS: Dict[str, str] = {
    "shodan_api_key":    "Shodan Search API key",
    "bing_api_key":      "Bing Web Search subscription key",
    "censys_api_id":     "Censys API ID",
    "censys_api_secret": "Censys API secret",
    "fofa_email":        "FOFA account email",
    "fofa_key":          "FOFA API key",
    "zoomeye_api_key":   "ZoomEye API key (JWT token)",
}

# Runtime settings  →  default value
SETTING_DEFAULTS: Dict[str, Any] = {
    "default_max_per_dork": 100,
    "request_timeout":      20,
    "google_delay":          4.0,
    "ddg_delay":             3.0,
    "yahoo_delay":           3.0,
    "shodan_delay":          1.0,
    "output_file":           "",
}

# Environment variables that map to credential keys
ENV_MAP: Dict[str, str] = {
    "shodan_api_key":    "SHODAN_API_KEY",
    "bing_api_key":      "BING_API_KEY",
    "censys_api_id":     "CENSYS_API_ID",
    "censys_api_secret": "CENSYS_API_SECRET",
    "fofa_email":        "FOFA_EMAIL",
    "fofa_key":          "FOFA_KEY",
    "zoomeye_api_key":   "ZOOMEYE_API_KEY",
}

# ---------------------------------------------------------------------------
# Config class
# ---------------------------------------------------------------------------


class Config:
    """
    Dict-like config object.  Holds merged credentials and settings.

    Do not instantiate directly — use load_config().
    """

    def __init__(self, data: Dict[str, Any]) -> None:
        self._data = data

    # -- Credentials --------------------------------------------------------

    def get(self, key: str, default: str = "") -> str:
        """Return credential value, or *default* if the key is not set."""
        return str(self._data.get("keys", {}).get(key, default))

    def set(self, key: str, value: str) -> None:
        self._data.setdefault("keys", {})[key] = value

    def delete(self, key: str) -> bool:
        keys = self._data.get("keys", {})
        if key in keys:
            del keys[key]
            return True
        return False

    def all_keys(self) -> Dict[str, str]:
        return dict(self._data.get("keys", {}))

    # -- Settings -----------------------------------------------------------

    def setting(self, name: str, default: Any = None) -> Any:
        """
        Return a runtime setting.
        Falls back to SETTING_DEFAULTS, then to *default*.
        Type-coerces to match the SETTING_DEFAULTS type.
        """
        fallback = default if default is not None else SETTING_DEFAULTS.get(name)
        raw = self._data.get("settings", {}).get(name, fallback)
        if fallback is not None and not isinstance(raw, type(fallback)):
            try:
                raw = type(fallback)(raw)
            except (ValueError, TypeError):
                raw = fallback
        return raw

    def set_setting(self, name: str, value: Any) -> None:
        self._data.setdefault("settings", {})[name] = value

    def all_settings(self) -> Dict[str, Any]:
        merged = dict(SETTING_DEFAULTS)
        merged.update(self._data.get("settings", {}))
        return merged

    # -- Serialization ------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version":  CONFIG_VERSION,
            "keys":     self._data.get("keys", {}),
            "settings": self._data.get("settings", {}),
        }


# ---------------------------------------------------------------------------
# Load / save
# ---------------------------------------------------------------------------


def _read_json(path: Path) -> Dict[str, Any]:
    """Read a JSON file silently, returning {} on any error."""
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh) or {}
    except (OSError, json.JSONDecodeError):
        return {}


def load_config(config_path: Optional[Path] = None) -> Config:
    """
    Load and merge configuration from all sources.

    Parameters
    ----------
    config_path : Path, optional
        Path to a local/custom config file that overrides the user config.
        Defaults to ./config.local.json.
    """
    # 1. User-level config (~/.php2shell/config.json)
    base = _read_json(CONFIG_FILE)

    # 2. Local / project-level override
    local = _read_json(config_path or LOCAL_FILE)

    # Merge: local wins over base
    merged_keys: Dict[str, str] = {}
    merged_keys.update(base.get("keys", {}))
    merged_keys.update(local.get("keys", {}))

    merged_settings: Dict[str, Any] = {}
    merged_settings.update(base.get("settings", {}))
    merged_settings.update(local.get("settings", {}))

    # 3. Environment variable overlay (highest priority)
    for cred_key, env_name in ENV_MAP.items():
        env_val = os.environ.get(env_name, "")
        if env_val:
            merged_keys[cred_key] = env_val

    return Config({
        "version":  CONFIG_VERSION,
        "keys":     merged_keys,
        "settings": merged_settings,
    })


def save_config(cfg: Config, path: Optional[Path] = None) -> None:
    """Persist config to the user-level config file (or a custom *path*)."""
    target = path or CONFIG_FILE
    target.parent.mkdir(parents=True, exist_ok=True)

    with open(target, "w", encoding="utf-8") as fh:
        json.dump(cfg.to_dict(), fh, indent=2)
        fh.write("\n")

    # Restrict permissions on POSIX (owner read/write only)
    if os.name == "posix":
        try:
            os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass


def _load_user_only() -> Config:
    """Load only the user-level config file — used by CLI mutators."""
    data = _read_json(CONFIG_FILE)
    return Config(data)


# ---------------------------------------------------------------------------
# API connection tests
# ---------------------------------------------------------------------------


def _test_shodan(cfg: Config):
    import requests as rq
    r = rq.get(
        "https://api.shodan.io/api-info",
        params={"key": cfg.get("shodan_api_key")},
        timeout=10,
    )
    if r.status_code == 200:
        d = r.json()
        return True, f"plan={d.get('plan','?')}  query_credits={d.get('query_credits','?')}"
    return False, f"HTTP {r.status_code}: {r.text[:120]}"


def _test_censys(cfg: Config):
    import requests as rq
    r = rq.get(
        "https://search.censys.io/api/v2/account",
        auth=(cfg.get("censys_api_id"), cfg.get("censys_api_secret")),
        timeout=10,
    )
    if r.status_code == 200:
        login = r.json().get("result", {}).get("login", "?")
        return True, f"account={login}"
    return False, f"HTTP {r.status_code}: {r.text[:120]}"


def _test_bing(cfg: Config):
    import requests as rq
    r = rq.get(
        "https://api.bing.microsoft.com/v7.0/search",
        params={"q": "php", "count": 1},
        headers={"Ocp-Apim-Subscription-Key": cfg.get("bing_api_key")},
        timeout=10,
    )
    if r.status_code == 200:
        return True, "key accepted"
    return False, f"HTTP {r.status_code}: {r.text[:120]}"


def _test_fofa(cfg: Config):
    import requests as rq
    r = rq.get(
        "https://fofa.info/api/v1/info/my",
        params={"email": cfg.get("fofa_email"), "key": cfg.get("fofa_key")},
        timeout=10,
    )
    if r.status_code == 200:
        d = r.json()
        if not d.get("error"):
            return True, f"user={d.get('username','?')}  fcoin={d.get('fcoin','?')}"
    return False, f"HTTP {r.status_code}: {r.text[:120]}"


def _test_zoomeye(cfg: Config):
    import requests as rq
    r = rq.get(
        "https://api.zoomeye.hk/resources-info",
        headers={"Authorization": f"JWT {cfg.get('zoomeye_api_key')}"},
        timeout=10,
    )
    if r.status_code == 200:
        d = r.json()
        plans = d.get("plan", [])
        name = plans[0].get("name", "?") if isinstance(plans, list) and plans else "?"
        return True, f"plan={name}"
    return False, f"HTTP {r.status_code}: {r.text[:120]}"


_TEST_FN = {
    "shodan":  _test_shodan,
    "bing":    _test_bing,
    "censys":  _test_censys,
    "fofa":    _test_fofa,
    "zoomeye": _test_zoomeye,
}

# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------


class Colors:
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"


def _c(text: str, color: str, no_color: bool) -> str:
    return text if no_color else f"{color}{text}{Colors.RESET}"


def mask(value: str, tail: int = 4) -> str:
    """Mask a credential, showing only the last *tail* characters."""
    if not value:
        return "(not set)"
    if len(value) <= tail:
        return "*" * len(value)
    return "*" * (len(value) - tail) + value[-tail:]


def _print_config(cfg: Config, no_color: bool = False, reveal: bool = False) -> None:
    sep = "─" * 54
    print(_c(f"\n{sep}", Colors.DIM, no_color))
    print(_c("  API KEYS", Colors.BOLD, no_color))
    print(_c(sep, Colors.DIM, no_color))
    for key, desc in CRED_KEYS.items():
        val = cfg.get(key)
        display = val if reveal else mask(val)
        color = Colors.GREEN if val else Colors.DIM
        print(f"  {_c(f'{key:<22}', Colors.CYAN, no_color)}  {_c(display, color, no_color)}")
        print(f"  {'':22}  {_c(desc, Colors.DIM, no_color)}")

    print(_c(f"\n{sep}", Colors.DIM, no_color))
    print(_c("  SETTINGS", Colors.BOLD, no_color))
    print(_c(sep, Colors.DIM, no_color))
    for name, default in SETTING_DEFAULTS.items():
        val = cfg.setting(name)
        is_default = (val == default)
        color = Colors.DIM if is_default else Colors.CYAN
        note = _c(" (default)", Colors.DIM, no_color) if is_default else ""
        print(f"  {name:<26}  {_c(str(val), color, no_color)}{note}")

    print(_c(f"\n{sep}", Colors.DIM, no_color))
    print(f"  user config  : {CONFIG_FILE}")
    print(f"  local config : {LOCAL_FILE}  (add to .gitignore)\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="config.py",
        description="API key & settings manager for php2shell-scanner / dork.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
credential keys:
  shodan_api_key     bing_api_key       zoomeye_api_key
  censys_api_id      censys_api_secret
  fofa_email         fofa_key

settings:
  default_max_per_dork   request_timeout
  google_delay           ddg_delay          yahoo_delay
  shodan_delay           output_file

config file : {CONFIG_FILE}
local file  : {LOCAL_FILE}

examples:
  python config.py --set shodan_api_key=sk-xxxxx
  python config.py --set censys_api_id=ID censys_api_secret=SECRET
  python config.py --set default_max_per_dork=200 request_timeout=30
  python config.py --show
  python config.py --show --reveal
  python config.py --delete bing_api_key
  python config.py --test shodan
  python config.py --test all
  python config.py --reset
""",
    )
    p.add_argument("--set",    nargs="+", metavar="KEY=VALUE",
                   help="Set credential key(s) or setting(s)")
    p.add_argument("--delete", nargs="+", metavar="KEY",
                   help="Remove key(s) from the config file")
    p.add_argument("--show",   action="store_true",
                   help="Display current config (credentials are masked)")
    p.add_argument("--reveal", action="store_true",
                   help="Show full credential values alongside --show")
    p.add_argument("--test",   nargs="+", metavar="BACKEND",
                   help=f"Test API credentials: {' '.join(_TEST_FN)} all")
    p.add_argument("--reset",  action="store_true",
                   help="Delete the user config file entirely")
    p.add_argument("--no-color", action="store_true")
    return p


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    no_color = args.no_color

    if not any([args.set, args.delete, args.show, args.test, args.reset]):
        parser.print_help()
        sys.exit(0)

    # --reset ----------------------------------------------------------------
    if args.reset:
        if CONFIG_FILE.exists():
            CONFIG_FILE.unlink()
            print(f"[ok] deleted {CONFIG_FILE}")
        else:
            print("[ok] nothing to reset")
        sys.exit(0)

    # --set / --delete  work on the user-level file only --------------------
    cfg = _load_user_only()

    if args.set:
        for pair in args.set:
            if "=" not in pair:
                print(f"[!] bad format '{pair}', expected KEY=VALUE", file=sys.stderr)
                sys.exit(1)
            key, _, value = pair.partition("=")
            key = key.strip()
            value = value.strip()
            if key in SETTING_DEFAULTS:
                cfg.set_setting(key, value)
                print(f"[ok] setting  {key} = {value}")
            elif key in CRED_KEYS:
                cfg.set(key, value)
                print(f"[ok] key      {key} = {mask(value)}")
            else:
                cfg.set(key, value)
                print(f"[warn] unknown key '{key}' saved (typo?)")
        save_config(cfg)
        print(f"[ok] saved → {CONFIG_FILE}")

    if args.delete:
        changed = False
        for key in args.delete:
            if cfg.delete(key):
                print(f"[ok] deleted '{key}'")
                changed = True
            else:
                print(f"[warn] '{key}' was not set")
        if changed:
            save_config(cfg)

    # --show  uses fully-merged config (env vars included) -------------------
    if args.show:
        _print_config(load_config(), no_color, args.reveal)

    # --test -----------------------------------------------------------------
    if args.test:
        try:
            import requests  # noqa: F401
        except ImportError:
            print("[!] pip install requests  (required for --test)", file=sys.stderr)
            sys.exit(1)

        full_cfg = load_config()
        targets: List[str] = (
            list(_TEST_FN.keys()) if "all" in args.test else args.test
        )

        for backend in targets:
            if backend not in _TEST_FN:
                valid = ", ".join(_TEST_FN)
                print(f"[!] unknown backend '{backend}'  (valid: {valid})")
                continue
            print(f"  testing {backend:<10}", end=" ", flush=True)
            try:
                ok, msg = _TEST_FN[backend](full_cfg)
            except Exception as exc:
                ok, msg = False, str(exc)
            tag = _c("[OK]",   Colors.GREEN, no_color) if ok \
                else _c("[FAIL]", Colors.RED,   no_color)
            print(f"{tag}  {msg}")


if __name__ == "__main__":
    main()
