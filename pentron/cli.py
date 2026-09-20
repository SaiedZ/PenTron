#!/usr/bin/env python3
"""
PENTRON - pentron/cli.py
Main CLI entry point. Wires db.py + tools.py + search.py + llm.py together.
Run with: python -m pentron.cli, or the `pentron` console script.
"""

import os
import sys

from .analysis_pipeline import analyse_and_save
from .db import (
    create_session,
    delete_fix,
    delete_full_session,
    delete_vulnerability,
    edit_fix,
    edit_summary_risk,
    edit_vulnerability,
    get_all_history,
    get_connection,
    get_fixes,
    get_session,
    get_settings,
    get_vulnerabilities,
    print_history,
    print_session,
    save_settings,
    update_session_status,
)
from .export import export_menu
from .providers import OllamaProvider
from .tools import (
    check_target_safety,
    discover_subdomains,
    interactive_tool_run,
)

# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────


def banner():
    os.system("clear")
    try:
        model = get_settings().get("model") or "unknown"
    except Exception:
        model = "unknown"
    print(f"""
\033[38;2;88;166;255m
    ██████╗ ███████╗███╗   ██╗████████╗██████╗  ██████╗ ███╗   ██╗
    ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║
    ██████╔╝█████╗  ██╔██╗ ██║   ██║   ██████╔╝██║   ██║██╔██╗ ██║
    ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██║   ██║██║╚██╗██║
    ██║     ███████╗██║ ╚████║   ██║   ██║  ██║╚██████╔╝██║ ╚████║
    ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
\033[0m
    \033[90mAI Penetration Testing Assistant  |  Model: {model}\033[0m
    \033[90m─────────────────────────────────────────────────────────────────────\033[0m
""")


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────


def divider(label=""):
    if label:
        print(f"\n\033[33m{'─' * 20} {label} {'─' * 20}\033[0m")
    else:
        print(f"\033[90m{'─' * 60}\033[0m")


def prompt(text):
    return input(f"\033[36m{text}\033[0m").strip()


def success(text):
    print(f"\033[92m[+] {text}\033[0m")


def warn(text):
    print(f"\033[93m[!] {text}\033[0m")


def error(text):
    print(f"\033[91m[✗] {text}\033[0m")


def info(text):
    print(f"\033[94m[*] {text}\033[0m")


def confirm(question: str) -> bool:
    ans = prompt(f"{question} [y/N]: ").lower()
    return ans == "y"


# ─────────────────────────────────────────────
# NEW SCAN
# ─────────────────────────────────────────────


def new_scan():
    divider("NEW SCAN")
    target = prompt("[?] Enter target IP or domain: ")
    if not target:
        warn("No target entered.")
        return

    unsafe = check_target_safety(target)
    if unsafe:
        error(unsafe)
        return

    # check if target was scanned before
    history = get_all_history()
    past = [row for row in history if row[1] == target]
    if past:
        warn(f"Target '{target}' has been scanned before ({len(past)} time(s)).")
        if not confirm("Continue with a new scan?"):
            return

    # create session in history table first
    sl_no = create_session(target)
    success(f"Session created — SL# {sl_no}")

    # run recon tools
    divider("RECON")
    info("Choose recon tools to run:")
    scan_settings = get_settings()
    delay = scan_settings.get("scan_delay_seconds", 0)
    user_agent = scan_settings.get("user_agent") or None
    subdomain_level = scan_settings.get("subdomain_discovery_level", 0)

    subdomain_text, allowed_subdomains = "", frozenset()
    if subdomain_level > 0:
        info("Discovering subdomains...")
        subdomain_text, allowed_subdomains = discover_subdomains(
            target, subdomain_level
        )
        print(subdomain_text)

    raw_scan = subdomain_text + interactive_tool_run(
        target, delay=delay, user_agent=user_agent
    )

    if not raw_scan.strip():
        warn("No scan data collected. Aborting.")
        update_session_status(sl_no, "failed")
        return

    # send to AI
    divider("AI ANALYSIS")
    status, result, analysis_error = analyse_and_save(
        sl_no, target, raw_scan, allowed_subdomains=allowed_subdomains
    )

    # ── save everything to DB ──────────────────
    divider("SAVING TO DATABASE")

    if status == "partial":
        warn(f"Recon saved, but AI analysis is partial: {analysis_error}")
    else:
        assert result is not None
        success(f"All data saved. SL# {sl_no} | Risk: {result['risk_level']}")
    divider()

    # show results and offer edit/delete
    data = get_session(sl_no)
    print_session(data)

    if confirm("Edit or delete anything in this session?"):
        edit_delete_menu(sl_no)


# ─────────────────────────────────────────────
# VIEW HISTORY
# ─────────────────────────────────────────────


def view_history():
    divider("SCAN HISTORY")
    rows = get_all_history()

    if not rows:
        warn("No scans in database yet.")
        return

    print_history(rows)

    sl_no_str = prompt("Enter SL# to view details (or press Enter to go back): ")
    if not sl_no_str:
        return

    try:
        sl_no = int(sl_no_str)
    except ValueError:
        error("Invalid SL#.")
        return

    data = get_session(sl_no)
    if not data["history"]:
        error(f"SL# {sl_no} not found.")
        return

    print_session(data)

    if confirm("Export this session?"):
        export_menu(data)

    if confirm("Edit or delete anything in this session?"):
        edit_delete_menu(sl_no)


# ─────────────────────────────────────────────
# SETTINGS
# ─────────────────────────────────────────────

_PROVIDERS = ["ollama", "openai", "anthropic", "google"]
_SUBDOMAIN_LEVEL_LABELS = {
    0: "0 — disabled (default)",
    1: "1 — passive (crt.sh)",
    2: "2 — active (crt.sh + subfinder)",
}


def _mask_api_key(key):
    if not key:
        return "not set"
    if len(key) <= 4:
        return "*" * len(key)
    return f"{'*' * (len(key) - 4)}{key[-4:]}"


def _print_settings(settings):
    provider = settings["provider"]
    print(f"  [1] Provider              : {provider}")
    if provider == "ollama":
        host = settings.get("ollama_host") or "localhost:11434"
        print(f"  [2] Ollama host            : {host}")
    else:
        print(
            f"  [2] API key                : {_mask_api_key(settings.get('api_key'))}"
        )
    print(f"  [3] Model                  : {settings['model']}")
    print(f"  [4] Ollama timeout (s)     : {settings['ollama_timeout']}")
    print(f"  [5] Summary timeout (s)    : {settings['summary_timeout']}")
    print(f"  [6] Delay between tools (s): {settings['scan_delay_seconds']}")
    ua = settings.get("user_agent") or "default (per-tool)"
    print(f"  [7] User-Agent             : {ua}")
    level = settings.get("subdomain_discovery_level", 0)
    print(f"  [8] Subdomain discovery    : {_SUBDOMAIN_LEVEL_LABELS.get(level, level)}")


def settings_menu():
    while True:
        settings = get_settings()
        divider("SETTINGS")
        _print_settings(settings)
        divider()
        info("Changes apply to the next scan — no restart needed.")

        choice = prompt("Field to change (or Enter to go back): ")
        if not choice:
            return

        if choice == "1":
            print("  Providers: " + ", ".join(_PROVIDERS))
            value = prompt("New provider: ").strip().lower()
            if value not in _PROVIDERS:
                error("Invalid provider.")
                continue
            save_settings(provider=value)
            success(f"Provider set to {value}.")

        elif choice == "2":
            if settings["provider"] == "ollama":
                value = prompt("New Ollama host (e.g. localhost:11434): ").strip()
                if value:
                    save_settings(ollama_host=value)
                    success("Ollama host updated.")
            else:
                value = prompt("New API key (leave blank to keep current): ").strip()
                if value:
                    save_settings(api_key=value)
                    success("API key updated.")

        elif choice == "3":
            if settings["provider"] == "ollama":
                host = settings.get("ollama_host") or "localhost:11434"
                models = OllamaProvider(settings["model"], host=host).list_models()
                if models:
                    print("  Installed Ollama models:")
                    for m in models:
                        print(f"    - {m}")
                else:
                    warn("Could not list Ollama models (unreachable, or none pulled).")
            value = prompt("New model name: ").strip()
            if value:
                save_settings(model=value)
                success("Model updated.")

        elif choice == "4":
            value = prompt("New Ollama timeout in seconds: ").strip()
            if value.isdigit():
                save_settings(ollama_timeout=int(value))
                success("Ollama timeout updated.")
            else:
                error("Must be a number.")

        elif choice == "5":
            value = prompt("New summary timeout in seconds: ").strip()
            if value.isdigit():
                save_settings(summary_timeout=int(value))
                success("Summary timeout updated.")
            else:
                error("Must be a number.")

        elif choice == "6":
            value = prompt(
                "New delay between recon tools in seconds (0 = off): "
            ).strip()
            if value.isdigit():
                save_settings(scan_delay_seconds=int(value))
                success("Delay updated.")
            else:
                error("Must be a number.")

        elif choice == "7":
            print("  Leave blank to reset to the default (each tool's own User-Agent).")
            value = prompt("New User-Agent: ")
            save_settings(user_agent=value or None)
            success("User-Agent updated.")

        elif choice == "8":
            print(
                "  0 = disabled, 1 = passive (crt.sh), 2 = active (crt.sh + subfinder)"
            )
            value = prompt("New subdomain discovery level: ").strip()
            if value in ("0", "1", "2"):
                save_settings(subdomain_discovery_level=int(value))
                success("Subdomain discovery level updated.")
            else:
                error("Must be 0, 1, or 2.")

        else:
            warn("Invalid choice.")


# ─────────────────────────────────────────────
# EDIT / DELETE MENU
# ─────────────────────────────────────────────


def edit_delete_menu(sl_no: int):
    while True:
        divider(f"EDIT / DELETE — SL# {sl_no}")
        print("  [1] Edit a vulnerability")
        print("  [2] Edit a fix")
        print("  [3] Edit risk level")
        print("  [4] Delete a vulnerability")
        print("  [5] Delete a fix")
        print("  [6] Delete FULL session (all tables)")
        print("  [7] Back")
        divider()

        choice = prompt("Choice: ")

        # ── EDIT VULNERABILITY ─────────────────
        if choice == "1":
            vulns = get_vulnerabilities(sl_no)
            if not vulns:
                warn("No vulnerabilities recorded for this session.")
                continue

            print("\n[ VULNERABILITIES ]")
            for v in vulns:
                print(f"  id={v[0]} | {v[2]} | {v[3]} | port {v[4]} | {v[5]}")

            vid = prompt("Enter vulnerability id to edit: ")
            if not vid.isdigit():
                error("Invalid id.")
                continue

            print("  Fields: vuln_name / severity / port / service / description")
            field = prompt("Field to edit: ").strip()
            value = prompt(f"New value for '{field}': ")
            edit_vulnerability(int(vid), field, value)

        # ── EDIT FIX ──────────────────────────
        elif choice == "2":
            fixes = get_fixes(sl_no)
            if not fixes:
                warn("No fixes recorded for this session.")
                continue

            print("\n[ FIXES ]")
            for f in fixes:
                print(f"  id={f[0]} | vuln_id={f[2]} | {f[3][:80]}")

            fid = prompt("Enter fix id to edit: ")
            if not fid.isdigit():
                error("Invalid id.")
                continue

            new_text = prompt("New fix text: ")
            edit_fix(int(fid), new_text)

        # ── EDIT RISK LEVEL ───────────────────
        elif choice == "3":
            print("  Options: CRITICAL / HIGH / MEDIUM / LOW")
            risk = prompt("New risk level: ").upper()
            if risk not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                error("Invalid risk level.")
                continue
            edit_summary_risk(sl_no, risk)

        # ── DELETE VULNERABILITY ──────────────
        elif choice == "4":
            vulns = get_vulnerabilities(sl_no)
            if not vulns:
                warn("No vulnerabilities to delete.")
                continue

            print("\n[ VULNERABILITIES ]")
            for v in vulns:
                print(f"  id={v[0]} | {v[2]} | {v[3]}")

            vid = prompt("Enter vulnerability id to delete: ")
            if not vid.isdigit():
                error("Invalid id.")
                continue

            if confirm(f"Delete vulnerability id={vid} and its linked fixes?"):
                delete_vulnerability(int(vid))

        # ── DELETE FIX ────────────────────────
        elif choice == "5":
            fixes = get_fixes(sl_no)
            if not fixes:
                warn("No fixes to delete.")
                continue

            print("\n[ FIXES ]")
            for f in fixes:
                print(f"  id={f[0]} | vuln_id={f[2]} | {f[3][:80]}")

            fid = prompt("Enter fix id to delete: ")
            if not fid.isdigit():
                error("Invalid id.")
                continue

            if confirm(f"Delete fix id={fid}?"):
                delete_fix(int(fid))

        # ── DELETE FULL SESSION ───────────────
        elif choice == "6":
            if confirm(
                f"\n\033[91mPermanently delete ENTIRE session SL# {sl_no} "
                f"from all tables?\033[0m"
            ):
                delete_full_session(sl_no)
                success(f"Session SL# {sl_no} wiped.")
                return  # go back to main menu

        # ── BACK ──────────────────────────────
        elif choice == "7":
            break

        else:
            warn("Invalid choice.")


# ─────────────────────────────────────────────
# DB CONNECTION CHECK
# ─────────────────────────────────────────────


def check_db():
    try:
        conn = get_connection()
        conn.close()
        return True
    except Exception as e:
        error(f"MariaDB connection failed: {e}")
        error("Make sure MariaDB is running: sudo systemctl start mariadb")
        return False


# ─────────────────────────────────────────────
# MAIN MENU
# ─────────────────────────────────────────────


def main_menu():
    while True:
        banner()
        print("  \033[92m[1]\033[0m  New Scan")
        print("  \033[92m[2]\033[0m  View History")
        print("  \033[92m[3]\033[0m  Settings")
        print("  \033[92m[4]\033[0m  Exit")
        divider()

        choice = prompt("pentron> ")

        if choice == "1":
            new_scan()
            input("\n\033[90mPress Enter to continue...\033[0m")

        elif choice == "2":
            view_history()
            input("\n\033[90mPress Enter to continue...\033[0m")

        elif choice == "3":
            settings_menu()

        elif choice == "4":
            print("\n\033[91m[*] Shutting down Pentron. Stay legal.\033[0m\n")
            sys.exit(0)

        else:
            warn("Invalid choice.")


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────


def main():
    if not check_db():
        sys.exit(1)
    main_menu()


if __name__ == "__main__":
    main()
