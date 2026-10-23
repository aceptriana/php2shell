#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════╗
║   PHP2Shell Scanner Suite  —  Interactive Launcher  ║
║   CVE-2026-109618 / CVE-2026-109619                 ║
║   Code By Acep  •  github.com/aceptriana            ║
╚══════════════════════════════════════════════════════╝
"""

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Third-party: colorama ──────────────────────────────────────────────────────
try:
    from colorama import init as _cinit, Fore, Back, Style
    _cinit(autoreset=True)
    _COLOR = True
except ImportError:
    _COLOR = False
    class _NC:
        def __getattr__(self, _): return ""
    Fore = Back = Style = _NC()

# ── Third-party: pyfiglet ──────────────────────────────────────────────────────
try:
    import pyfiglet as _fig
    _FIG = True
except ImportError:
    _FIG = False

# ── Config module (optional) ───────────────────────────────────────────────────
try:
    from config import load_config as _load_cfg, mask as _mask
    _CFG_MODULE = True
except ImportError:
    _CFG_MODULE = False
    def _load_cfg(*_, **__): return None  # type: ignore[misc]
    def _mask(v, **__): return "••••" + v[-4:] if v else "(not set)"

# ── Paths ──────────────────────────────────────────────────────────────────────
_HERE     = Path(__file__).parent
_SCANNER  = _HERE / "scanner.py"
_DORKER   = _HERE / "dork.py"
_CONFIGPY = _HERE / "config.py"
_DORKFILE = _HERE / "dork.txt"
_TARGETS  = _HERE / "targets.txt"
_PY       = sys.executable

# ── Metadata ───────────────────────────────────────────────────────────────────
VERSION = "1.0"
AUTHOR  = "Acep"
GITHUB  = "github.com/aceptriana"
CVES    = "CVE-2026-109618 / CVE-2026-109619"
W       = 62   # box inner width

# ── Backend catalog ────────────────────────────────────────────────────────────
# (id, display, cred_key_for_check, flag_for_dork.py)
BACKENDS: List[Tuple[str, str, Optional[str], str]] = [
    ("google",   "Google",       None,                 "--google"),
    ("ddg",      "DuckDuckGo",   None,                 "--ddg"),
    ("yahoo",    "Yahoo",        None,                 "--yahoo"),
    ("bing",     "Bing",         "bing_api_key",       "--bing"),
    ("shodan",   "Shodan",       "shodan_api_key",     "--shodan"),
    ("censys",   "Censys",       "censys_api_id",      "--censys"),
    ("fofa",     "FOFA",         "fofa_email",         "--fofa"),
    ("zoomeye",  "ZoomEye",      "zoomeye_api_key",    "--zoomeye"),
]

# ══════════════════════════════════════════════════════════════════════════════
#  Color helpers
# ══════════════════════════════════════════════════════════════════════════════

def _R(t): return f"{Fore.RED}{Style.BRIGHT}{t}{Style.RESET_ALL}"
def _G(t): return f"{Fore.GREEN}{Style.BRIGHT}{t}{Style.RESET_ALL}"
def _Y(t): return f"{Fore.YELLOW}{t}{Style.RESET_ALL}"
def _C(t): return f"{Fore.CYAN}{t}{Style.RESET_ALL}"
def _M(t): return f"{Fore.MAGENTA}{t}{Style.RESET_ALL}"
def _W(t): return f"{Style.BRIGHT}{Fore.WHITE}{t}{Style.RESET_ALL}"
def _D(t): return f"{Style.DIM}{t}{Style.RESET_ALL}"

def _strip_ansi(s: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", s)

def _vlen(s: str) -> int:
    """Visual length of a string (ignoring ANSI codes)."""
    return len(_strip_ansi(s))


# ══════════════════════════════════════════════════════════════════════════════
#  Terminal helpers
# ══════════════════════════════════════════════════════════════════════════════

def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")

def press_enter(msg: str = "Press Enter to continue...") -> None:
    print()
    try:
        input(_D(f"  {msg}"))
    except (EOFError, KeyboardInterrupt):
        pass

def _ask(label: str, default: str = "") -> str:
    hint = _D(f" [{default}]") if default else ""
    try:
        raw = input(f"  {_Y('?')} {label}{hint}: ").strip()
    except (EOFError, KeyboardInterrupt):
        return default
    return raw if raw else default

def _choice(prompt_str: str = "") -> str:
    try:
        return input(f"\n  {_Y('>')} {prompt_str}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return "0"


# ══════════════════════════════════════════════════════════════════════════════
#  Box drawing
# ══════════════════════════════════════════════════════════════════════════════

def _row(text: str, width: int, vc: str = "│", pad: int = 2) -> str:
    inner = width - 2 - pad * 2
    vlen  = _vlen(text)
    space = max(0, inner - vlen)
    return f"{vc}{' ' * pad}{text}{' ' * space}{' ' * pad}{vc}"

def _hline(width: int, lc: str, rc: str, fc: str = "─") -> str:
    return lc + fc * (width - 2) + rc

def print_box(
    title: str,
    rows: List[str],
    width: int = W,
    color: str = "",
    title_color: str = "",
    double: bool = False,
) -> None:
    c  = color or Fore.CYAN
    tc = title_color or (Style.BRIGHT + Fore.WHITE)
    r  = Style.RESET_ALL
    if double:
        tl, tr, bl, br, h, v = "╔", "╗", "╚", "╝", "═", "║"
        ml, mr = "╠", "╣"
    else:
        tl, tr, bl, br, h, v = "┌", "┐", "└", "┘", "─", "│"
        ml, mr = "├", "┤"

    print()
    print(f"  {c}{_hline(width, tl, tr, h)}{r}")
    if title:
        print(f"  {c}{_row(tc + title + r + c, width, v)}{r}")
        print(f"  {c}{_hline(width, ml, mr, h)}{r}")
    print(f"  {c}{_row('', width, v)}{r}")
    for row in rows:
        print(f"  {c}{_row(row, width, v)}{r}")
    print(f"  {c}{_row('', width, v)}{r}")
    print(f"  {c}{_hline(width, bl, br, h)}{r}")


def print_sep(width: int = W, color: str = "") -> None:
    c = color or Fore.CYAN
    print(f"\n  {c}{'─' * width}{Style.RESET_ALL}\n")


def print_section(title: str, color: str = "") -> None:
    c = color or Fore.CYAN
    print(f"\n  {c}┌{'─' * (len(title) + 2)}┐{Style.RESET_ALL}")
    print(f"  {c}│ {Style.BRIGHT}{Fore.WHITE}{title}{Style.RESET_ALL}{c} │{Style.RESET_ALL}")
    print(f"  {c}└{'─' * (len(title) + 2)}┘{Style.RESET_ALL}")


def _mi(num: str, label: str, desc: str = "", width: int = W) -> str:
    """Render a single menu item row as a string."""
    n  = _Y(f"[{num}]")
    lb = _W(f"{label:<20}")
    ds = _D(desc) if desc else ""
    return f"  {n}  {lb}  {ds}"


# ══════════════════════════════════════════════════════════════════════════════
#  Banner
# ══════════════════════════════════════════════════════════════════════════════

_FALLBACK_ART = [
    r"  ____  _   _ ____    ____    ____  _   _ _____ _     _     ",
    r" |  _ \| | | |  _ \  |___ \  / ___|| | | | ____| |   | |   ",
    r" | |_) | |_| | |_) |   __) | \___ \| |_| |  _| | |   | |   ",
    r" |  __/|  _  |  __/   / __/   ___) |  _  | |___| |___| |___",
    r" |_|   |_| |_|_|     |_____| |____/|_| |_|_____|_____|_____|",
]

def print_banner() -> None:
    clear()
    print()
    # Art
    if _FIG:
        try:
            art = _fig.figlet_format("PHP2SHELL", font="slant")
            for line in art.splitlines():
                if line.strip():
                    print(f"  {Fore.RED}{Style.BRIGHT}{line}{Style.RESET_ALL}")
        except Exception:
            for line in _FALLBACK_ART:
                print(f"{Fore.RED}{Style.BRIGHT}{line}{Style.RESET_ALL}")
    else:
        for line in _FALLBACK_ART:
            print(f"{Fore.RED}{Style.BRIGHT}{line}{Style.RESET_ALL}")

    # Subtitle bar
    print()
    print(f"  {Fore.CYAN}{'═' * W}{Style.RESET_ALL}")
    print(f"  {Style.BRIGHT}{Fore.WHITE}{'PHP2Shell Vulnerability Scanner Suite v' + VERSION:^{W}}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}{CVES:^{W}}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}{'═' * W}{Style.RESET_ALL}")
    print(f"  {Style.DIM}{f'Code By {AUTHOR}  •  {GITHUB}':^{W}}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}{'═' * W}{Style.RESET_ALL}")
    print()


# ══════════════════════════════════════════════════════════════════════════════
#  Subprocess runner
# ══════════════════════════════════════════════════════════════════════════════

def run_live(cmd: List[str], label: str = "") -> int:
    """Run a command and stream its combined stdout+stderr to the terminal."""
    sep = Fore.CYAN + "─" * W + Style.RESET_ALL
    print(f"\n  {sep}")
    if label:
        print(f"  {_C('running')} {_W(label)}")
    print(f"  {_D(' '.join(cmd[:4]) + ' ...')}")
    print(f"  {sep}\n")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        assert proc.stdout is not None
        for line in iter(proc.stdout.readline, ""):
            print(f"  {line}", end="", flush=True)
        proc.wait()
        rc = proc.returncode
    except KeyboardInterrupt:
        print(f"\n  {_Y('[!] Interrupted')}")
        try:
            proc.terminate()
        except Exception:
            pass
        rc = 130
    except FileNotFoundError as exc:
        print(f"  {_R(f'[!] Not found: {exc}')}")
        rc = 127
    except Exception as exc:
        print(f"  {_R(f'[!] {exc}')}")
        rc = 1

    print(f"\n  {sep}")
    tag = _G("[+] Finished") if rc in (0, 130) else _R(f"[!] Exit code {rc}")
    print(f"  {tag}\n")
    return rc


# ══════════════════════════════════════════════════════════════════════════════
#  Config status loader
# ══════════════════════════════════════════════════════════════════════════════

def _load_cfg_safe():
    if not _CFG_MODULE:
        return None
    try:
        return _load_cfg()
    except Exception:
        return None

def _key_status(cfg, cred_key: Optional[str]) -> str:
    """Return colored key status string for a backend."""
    if cred_key is None:
        return _G("free  ")
    if cfg is None:
        return _D("no cfg")
    val = cfg.get(cred_key)
    return _G(_mask(val)) if val else _R("not set")


# ══════════════════════════════════════════════════════════════════════════════
#  Backend selector (used by dork menu)
# ══════════════════════════════════════════════════════════════════════════════

def select_backends(cfg) -> List[str]:
    """
    Interactive backend toggle screen.
    Returns list of backend flags (e.g. ["--google", "--shodan"])
    or empty list if user went back.
    """
    # Default: free backends enabled
    sel: Dict[str, bool] = {b[0]: (b[2] is None) for b in BACKENDS}

    while True:
        clear()
        print_banner()
        print_section("BACKEND SELECTION", Fore.CYAN)
        print(f"\n  {_D('Toggle: press number  |  a=all  n=none  r=run  b=back')}\n")

        for i, (bid, bname, cred_key, _) in enumerate(BACKENDS, 1):
            tick  = _G("[✓]") if sel[bid] else _D("[ ]")
            kstat = _key_status(cfg, cred_key)
            row   = f"  {_Y(f'[{i}]')}  {tick}  {Fore.WHITE}{bname:<14}{Style.RESET_ALL}  {kstat}"
            print(row)

        print(f"\n  {Fore.CYAN}{'─' * 40}{Style.RESET_ALL}")
        ch = _choice()

        if ch == "b":
            return []
        elif ch == "r":
            chosen = [BACKENDS[i][3] for i, (bid, *_) in enumerate(BACKENDS) if sel[bid]]
            if not chosen:
                print(f"\n  {_Y('[!] Select at least one backend.')}")
                time.sleep(1.2)
                continue
            return chosen
        elif ch == "a":
            sel = {b[0]: True for b in BACKENDS}
        elif ch == "n":
            sel = {b[0]: False for b in BACKENDS}
        elif ch.isdigit():
            idx = int(ch) - 1
            if 0 <= idx < len(BACKENDS):
                bid = BACKENDS[idx][0]
                sel[bid] = not sel[bid]


# ══════════════════════════════════════════════════════════════════════════════
#  MENU: Dork
# ══════════════════════════════════════════════════════════════════════════════

def menu_dork() -> None:
    cfg = _load_cfg_safe()

    # Editable defaults
    state = {
        "max":    "100",
        "output": str(_TARGETS),
        "file":   str(_DORKFILE) if _DORKFILE.exists() else "",
    }

    while True:
        print_banner()
        print_section("AUTO DORK", Fore.CYAN)

        rows = [
            f"  {_Y('[1]')}  {_W('Select Backends')}  {_D('Choose search engines')}",
            f"  {_Y('[2]')}  {_W('Max per dork   ')}  {_C(state['max'])} results",
            f"  {_Y('[3]')}  {_W('Output file    ')}  {_C(state['output'])}",
            f"  {_Y('[4]')}  {_W('Dork file      ')}  "
            + (_C(state['file']) if state['file'] else _D('(built-in dorks)')),
            "",
            f"  {_Y('[r]')}  {_W('Run Dork       ')}  {_D('Start scanning')}",
            f"  {_Y('[0]')}  {_W('Back')}",
        ]
        for r in rows:
            print(r)
        print_sep()

        ch = _choice()

        if ch in ("0", "b", "q"):
            return
        elif ch == "1":
            flags = select_backends(cfg)
            if not flags:
                continue
            # Build and run dork command
            cmd = [_PY, str(_DORKER)] + flags
            cmd += ["-n", state["max"], "-o", state["output"]]
            if state["file"]:
                cmd += ["--dork-file", state["file"]]
            run_live(cmd, "dork.py")
            press_enter()
        elif ch == "2":
            state["max"] = _ask("Max results per dork", state["max"])
        elif ch == "3":
            state["output"] = _ask("Output file", state["output"])
        elif ch == "4":
            state["file"] = _ask("Extra dork file (blank = built-in)", state["file"])
        elif ch == "r":
            # Run with currently selected defaults (all free backends)
            free_flags = [b[3] for b in BACKENDS if b[2] is None]
            cmd = [_PY, str(_DORKER)] + free_flags
            cmd += ["-n", state["max"], "-o", state["output"]]
            if state["file"]:
                cmd += ["--dork-file", state["file"]]
            run_live(cmd, "dork.py  (free backends)")
            press_enter()


# ══════════════════════════════════════════════════════════════════════════════
#  MENU: Scan
# ══════════════════════════════════════════════════════════════════════════════

def menu_scan() -> None:
    state = {
        "targets": str(_TARGETS),
        "threads": "10",
        "timeout": "60",
        "output":  "results.json",
        "sapi":    "auto",
        "verbose": False,
        "insecure": False,
    }

    while True:
        print_banner()
        print_section("SCAN TARGETS", Fore.GREEN)

        tf_exists = Path(state["targets"]).exists()
        tf_info   = (_G("exists") if tf_exists else _R("not found"))

        rows = [
            f"  {_Y('[1]')}  {_W('Targets file')}    {_C(state['targets'])}  {tf_info}",
            f"  {_Y('[2]')}  {_W('Threads     ')}    {_C(state['threads'])}",
            f"  {_Y('[3]')}  {_W('Timeout (s) ')}    {_C(state['timeout'])}",
            f"  {_Y('[4]')}  {_W('Output file ')}    {_C(state['output'])}",
            f"  {_Y('[5]')}  {_W('SAPI mode   ')}    {_C(state['sapi'])}  "
            + _D("(auto / fpm / mod_php)"),
            f"  {_Y('[6]')}  {_W('Verbose     ')}    "
            + (_G("on ") if state["verbose"] else _D("off")),
            f"  {_Y('[7]')}  {_W('Skip TLS    ')}    "
            + (_G("on ") if state["insecure"] else _D("off")),
            "",
            f"  {_Y('[r]')}  {_W('Run Scanner ')}    {_D('Start vulnerability scan')}",
            f"  {_Y('[0]')}  {_W('Back')}",
        ]
        for r in rows:
            print(r)
        print_sep()

        ch = _choice()

        if ch in ("0", "b", "q"):
            return
        elif ch == "1":
            state["targets"] = _ask("Targets file", state["targets"])
        elif ch == "2":
            state["threads"] = _ask("Threads", state["threads"])
        elif ch == "3":
            state["timeout"] = _ask("Timeout (seconds)", state["timeout"])
        elif ch == "4":
            state["output"]  = _ask("Output file (.json)", state["output"])
        elif ch == "5":
            v = _ask("SAPI (auto/fpm/mod_php)", state["sapi"])
            if v in ("auto", "fpm", "mod_php"):
                state["sapi"] = v
            else:
                print(f"  {_Y('[!] Must be: auto  fpm  mod_php')}")
                time.sleep(1)
        elif ch == "6":
            state["verbose"] = not state["verbose"]
        elif ch == "7":
            state["insecure"] = not state["insecure"]
        elif ch == "r":
            if not Path(state["targets"]).exists():
                print(f"\n  {_R('[!] Targets file not found:')} {state['targets']}")
                print(f"  {_D('Run Auto Dork first to collect targets.')}")
                press_enter()
                continue
            cmd = [
                _PY, str(_SCANNER),
                "-l", state["targets"],
                "-t", state["threads"],
                "--timeout", state["timeout"],
                "-o", state["output"],
                "--sapi", state["sapi"],
            ]
            if state["verbose"]:
                cmd.append("-v")
            if state["insecure"]:
                cmd.append("-k")
            run_live(cmd, "scanner.py")
            press_enter()


# ══════════════════════════════════════════════════════════════════════════════
#  MENU: Config
# ══════════════════════════════════════════════════════════════════════════════

def menu_config() -> None:
    while True:
        print_banner()
        print_section("CONFIG MANAGER", Fore.MAGENTA)

        rows = [
            f"  {_Y('[1]')}  {_W('Show config    ')}  {_D('Display all keys (masked)')}",
            f"  {_Y('[2]')}  {_W('Set a key      ')}  {_D('python config.py --set KEY=VALUE')}",
            f"  {_Y('[3]')}  {_W('Delete a key   ')}  {_D('Remove a stored key')}",
            f"  {_Y('[4]')}  {_W('Test connections')} {_D('Verify API credentials live')}",
            f"  {_Y('[5]')}  {_W('Change settings')}  {_D('Delays, timeouts, defaults')}",
            f"  {_Y('[6]')}  {_W('Reset config   ')}  {_R('Delete all stored keys')}",
            "",
            f"  {_Y('[0]')}  {_W('Back')}",
        ]
        for r in rows:
            print(r)
        print_sep()

        ch = _choice()

        if ch in ("0", "b", "q"):
            return
        elif ch == "1":
            run_live([_PY, str(_CONFIGPY), "--show"], "config.py --show")
            press_enter()
        elif ch == "2":
            kv = _ask("KEY=VALUE  (e.g. shodan_api_key=abc123)")
            if "=" in kv:
                run_live([_PY, str(_CONFIGPY), "--set", kv], "config.py --set")
            else:
                print(f"  {_R('[!] Format: KEY=VALUE')}")
            press_enter()
        elif ch == "3":
            key = _ask("Key to delete  (e.g. bing_api_key)")
            if key:
                run_live([_PY, str(_CONFIGPY), "--delete", key], "config.py --delete")
            press_enter()
        elif ch == "4":
            print(f"\n  {_D('Available: shodan  bing  censys  fofa  zoomeye  all')}")
            backend = _ask("Backend to test", "all")
            run_live([_PY, str(_CONFIGPY), "--test", backend], "config.py --test")
            press_enter()
        elif ch == "5":
            print(f"\n  {_D('Settings: default_max_per_dork  request_timeout  google_delay  ddg_delay')}")
            kv = _ask("SETTING=VALUE  (e.g. default_max_per_dork=200)")
            if "=" in kv:
                run_live([_PY, str(_CONFIGPY), "--set", kv], "config.py --set")
            press_enter()
        elif ch == "6":
            print(f"\n  {_R('[!] This will delete all stored API keys!')}")
            raw = _ask("Type YES to confirm")
            if raw == "YES":
                run_live([_PY, str(_CONFIGPY), "--reset"], "config.py --reset")
            else:
                print(f"  {_D('Cancelled.')}")
            press_enter()


# ══════════════════════════════════════════════════════════════════════════════
#  MENU: Dork Catalog
# ══════════════════════════════════════════════════════════════════════════════

def menu_catalog() -> None:
    """Display dork.txt with basic paging, or fall back to the built-in list."""
    clear()
    print_banner()
    print_section("DORK CATALOG", Fore.YELLOW)

    lines: List[str] = []
    if _DORKFILE.exists():
        try:
            lines = _DORKFILE.read_text(encoding="utf-8").splitlines()
        except Exception:
            pass

    if not lines:
        # Fall back to listing from dork.py
        try:
            result = subprocess.run(
                [_PY, str(_DORKER), "--list-dorks", "--no-color"],
                capture_output=True, text=True, encoding="utf-8"
            )
            lines = result.stdout.splitlines()
        except Exception:
            lines = ["[!] Could not load dork catalog."]

    # Paginate
    page_size = 28
    total     = len(lines)
    page      = 0
    max_page  = max(0, (total - 1) // page_size)

    while True:
        clear()
        print_banner()
        header = f"DORK CATALOG  —  {_DORKFILE.name if _DORKFILE.exists() else 'built-in'}"
        print_section(header, Fore.YELLOW)
        print(f"  {_D(f'Page {page+1}/{max_page+1}  •  {total} lines total')}\n")

        start = page * page_size
        chunk = lines[start: start + page_size]
        for ln in chunk:
            if ln.startswith("#"):
                print(f"  {Style.DIM}{Fore.GREEN}{ln}{Style.RESET_ALL}")
            elif ":" in ln and not ln.startswith(" "):
                backend, _, dork = ln.partition(":")
                print(f"  {_C(backend + ':')}{dork}")
            else:
                print(f"  {ln}")

        print(f"\n  {Fore.CYAN}{'─' * W}{Style.RESET_ALL}")
        nav = []
        if page > 0:
            nav.append(_Y("[p] Prev"))
        if page < max_page:
            nav.append(_Y("[n] Next"))
        nav.append(_Y("[b] Back"))
        print(f"  {'  '.join(nav)}")

        ch = _choice()
        if ch in ("0", "b", "q"):
            return
        elif ch == "n" and page < max_page:
            page += 1
        elif ch == "p" and page > 0:
            page -= 1


# ══════════════════════════════════════════════════════════════════════════════
#  MENU: View Results
# ══════════════════════════════════════════════════════════════════════════════

def menu_results() -> None:
    while True:
        clear()
        print_banner()
        print_section("SCAN RESULTS", Fore.GREEN)

        # Find .json files in current dir
        json_files = sorted(_HERE.glob("*.json"))
        if not json_files:
            print(f"\n  {_D('No result files found in')} {_C(str(_HERE))}")
            print(f"  {_D('Run the scanner with -o results.json to save results.')}")
            press_enter()
            return

        print(f"\n  {_D('Select a result file:')}\n")
        for i, f in enumerate(json_files, 1):
            size = f.stat().st_size
            print(f"  {_Y(f'[{i}]')}  {_W(f.name):<30}  {_D(f'{size:,} bytes')}")
        print(f"\n  {_Y('[0]')}  {_W('Back')}")

        ch = _choice()
        if ch in ("0", "b", "q"):
            return
        if not ch.isdigit() or not (1 <= int(ch) <= len(json_files)):
            continue

        selected = json_files[int(ch) - 1]
        _show_results(selected)


def _show_results(path: Path) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"\n  {_R(f'[!] Cannot parse {path.name}: {exc}')}")
        press_enter()
        return

    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        print(f"  {_R('[!] Unexpected result format.')}")
        press_enter()
        return

    vuln    = [r for r in data if r.get("vulnerable") is True]
    fixed   = [r for r in data if r.get("verdict") == "FIXED"]
    incon   = [r for r in data if r.get("verdict") in ("INCONCLUSIVE", "ERROR")]
    no_sig  = [r for r in data if r.get("verdict") == "NO SIGNAL"]

    summary = [
        f"{_G('VULNERABLE')}   : {_W(str(len(vuln)))}",
        f"{_Y('FIXED')}        : {len(fixed)}",
        f"{_D('INCONCLUSIVE')} : {len(incon)}",
        f"{_D('NO SIGNAL')}    : {len(no_sig)}",
        f"{_C('TOTAL')}        : {len(data)}",
    ]
    print_box(f"Results: {path.name}", summary, color=Fore.GREEN, double=True)

    if vuln:
        print(f"\n  {_R('── VULNERABLE HOSTS ─────────────────────────────────────')}\n")
        for r in vuln:
            host   = r.get("host", "?")
            sapi   = r.get("sapi", "?")
            reason = r.get("reason", "")[:60]
            pb     = r.get("powered_by", "")
            print(f"  {_R('[VULN]')} {_W(host)}")
            if pb:
                print(f"         {_D('version  :')} {_Y(pb)}")
            print(f"         {_D('sapi     :')} {_C(sapi)}")
            print(f"         {_D('reason   :')} {_D(reason)}")
            print()

    press_enter("Press Enter to go back...")


# ══════════════════════════════════════════════════════════════════════════════
#  MENU: About
# ══════════════════════════════════════════════════════════════════════════════

def menu_about() -> None:
    cfg = _load_cfg_safe()
    rows = [
        _W("PHP2Shell Scanner Suite"),
        _D(f"Version {VERSION}"),
        "",
        f"  Author   {_C(AUTHOR)}",
        f"  GitHub   {_C(GITHUB)}",
        f"  CVEs     {_Y(CVES)}",
        "",
        _D("Tools in this suite:"),
        f"  {_C('scanner.py')}  Probe targets for php2shell vulnerability",
        f"  {_C('dork.py')}     Auto-discover targets via OSINT backends",
        f"  {_C('config.py')}   Manage API keys and settings",
        f"  {_C('dork.txt')}    Dork catalog (82+ queries across 8 backends)",
        "",
        _D("Installed status:"),
        f"  colorama  {'  ' + _G('ok') if _COLOR else '  ' + _R('missing')}",
        f"  pyfiglet  {'  ' + _G('ok') if _FIG else '  ' + _R('missing  (pip install pyfiglet)')}",
        f"  config.py {'  ' + _G('loaded') if _CFG_MODULE else '  ' + _R('not found')}",
    ]
    print_box("ABOUT", rows, color=Fore.MAGENTA, double=True)
    press_enter()


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ══════════════════════════════════════════════════════════════════════════════

def main_menu() -> None:
    while True:
        print_banner()

        cfg     = _load_cfg_safe()
        keys_ok = sum(
            1 for b in BACKENDS
            if b[2] and cfg and cfg.get(b[2])
        )
        keys_str = (
            _G(f"{keys_ok} API key(s) configured")
            if keys_ok > 0
            else _Y("no API keys  (run Config Manager)")
        )

        rows = [
            f"  {_Y('[1]')}  {_W('Auto Dork      ')}  {_D('Find vulnerable PHP targets')}",
            f"  {_Y('[2]')}  {_W('Scan Targets   ')}  {_D('Test targets for php2shell')}",
            f"  {_Y('[3]')}  {_W('Config Manager ')}  {keys_str}",
            f"  {_Y('[4]')}  {_W('Dork Catalog   ')}  {_D('Browse all built-in dorks')}",
            f"  {_Y('[5]')}  {_W('View Results   ')}  {_D('Browse saved scan results')}",
            f"  {_Y('[6]')}  {_W('About          ')}  {_D('Info & credits')}",
            "",
            f"  {_Y('[0]')}  {_W('Exit')}",
        ]
        print_box("MAIN MENU", rows, color=Fore.CYAN, double=True)

        ch = _choice()

        if ch == "1":
            menu_dork()
        elif ch == "2":
            menu_scan()
        elif ch == "3":
            menu_config()
        elif ch == "4":
            menu_catalog()
        elif ch == "5":
            menu_results()
        elif ch == "6":
            clear()
            print_banner()
            menu_about()
        elif ch in ("0", "q", "exit"):
            clear()
            print(f"\n  {_C('Goodbye!')}  {_D(f'Code By {AUTHOR}  •  {GITHUB}')}\n")
            sys.exit(0)


# ══════════════════════════════════════════════════════════════════════════════
#  Entry point
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if not _COLOR:
        print(
            "[tip] pip install colorama pyfiglet  "
            "for a better looking interface",
            file=sys.stderr,
        )
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n  {_D(f'Code By {AUTHOR}  •  {GITHUB}')}\n")
        sys.exit(0)
