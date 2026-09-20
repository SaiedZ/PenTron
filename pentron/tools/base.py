"""
Generic subprocess runner shared by every tool module.

Other modules in this package call it as `from . import base` +
`base.run_tool(...)` — never `from .base import run_tool` directly — so a
test can monkeypatch the single `pentron.tools.base.run_tool` target and
have it take effect no matter which tool module ends up calling it.
"""

import subprocess
import time


def run_tool(
    command: list, timeout: int = 120, retries: int = 0, retry_delay: float = 2.0
) -> str:
    """
    Execute a shell command, return combined stdout + stderr as string.
    Never crashes the program — always returns something.

    Retries only on a timeout, up to `retries` extra attempts, since that's
    the one failure mode that's plausibly a transient network hiccup rather
    than a deterministic outcome (tool not found, target actually filtered,
    a completed scan) that re-running would just reproduce.
    """
    attempt = 0
    while True:
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=timeout
            )
            output = result.stdout.strip()
            errors = result.stderr.strip()

            if output and errors:
                return output + "\n[STDERR]\n" + errors
            elif output:
                return output
            elif errors:
                return errors
            else:
                return "[!] Tool returned no output."

        except subprocess.TimeoutExpired:
            if attempt < retries:
                attempt += 1
                print(
                    f"  [!] Timed out after {timeout}s, "
                    f"retrying ({attempt}/{retries})..."
                )
                time.sleep(retry_delay)
                continue
            tried = f" (tried {attempt + 1}x)" if retries else ""
            return f"[!] Timed out after {timeout}s{tried}: {' '.join(command)}"
        except FileNotFoundError:
            return (
                f"[!] Tool not found: {command[0]} — install it with: "
                f"sudo apt install {command[0]}"
            )
        except Exception as e:
            return f"[!] Unexpected error running {command[0]}: {e}"
