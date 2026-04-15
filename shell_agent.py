#!/usr/bin/env python3
"""
shell_agent — interactive terminal agent that translates natural language
into shell commands using a local LLM (LMStudio / OpenAI-compatible API).
"""

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# ── .env loader ──────────────────────────────────────────────────────────────


def load_dotenv(env_path: Path) -> None:
    """Minimal .env loader — no external dependency required."""
    if not env_path.is_file():
        return
    with env_path.open() as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


load_dotenv(Path(__file__).parent / ".env")

# ── Dependencies ─────────────────────────────────────────────────────────────

try:
    from openai import OpenAI
except ImportError:
    print("Missing dependency: openai.  Run:  pip install openai")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.prompt import Prompt, Confirm
    from rich.markdown import Markdown
    from rich.rule import Rule
    from rich.live import Live
    from rich.spinner import Spinner
except ImportError:
    print("Missing dependency: rich.  Run:  pip install rich")
    sys.exit(1)

console = Console()

# ── Configuration ────────────────────────────────────────────────────────────

LMSTUDIO_BASE_URL = os.getenv("LMSTUDIO_URL", "http://localhost:1234/v1")
LMSTUDIO_API_KEY = os.getenv("LMSTUDIO_API_KEY", "lm-studio")
MODEL = os.getenv("LMSTUDIO_MODEL", "local-model")

WORKING_DIR = os.getenv("SHELL_AGENT_CWD", str(Path.home()))
OUTPUT_CAP = int(os.getenv("SHELL_AGENT_OUTPUT_CAP", "8000"))
MAX_ITERATIONS = int(os.getenv("SHELL_AGENT_MAX_ITER", "15"))
MAX_HISTORY = int(os.getenv("SHELL_AGENT_MAX_HISTORY", "40"))

# ── Security ─────────────────────────────────────────────────────────────────

# Commands that are always blocked — no bypass
BLOCKED_COMMANDS = [
    r"\brm\s+(-[a-zA-Z]*)?.*\s+/\s*$",       # rm /  or rm -rf /
    r"\bmkfs\b",                                # format disk
    r"\bdd\b.*\bof=/dev/",                      # dd to raw device
    r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;",          # fork bomb
    r"\bshutdown\b",                            # shutdown
    r"\breboot\b",                              # reboot
    r"\binit\s+0\b",                            # halt
    r"\bhalt\b",                                # halt
    r"\bpoweroff\b",                            # poweroff
    r">\s*/dev/sd[a-z]",                        # write to raw disk
    r"\bchmod\s+(-[a-zA-Z]*\s+)?777\s+/",      # chmod 777 on root
    r"\bchown\s+.*\s+/\s*$",                    # chown on root
]

# Commands that require explicit user confirmation
DANGEROUS_PATTERNS = [
    (r"\brm\s+(-[a-zA-Z]*\s+)*", "Eliminazione file/cartelle"),
    (r"\brmdir\b", "Eliminazione directory"),
    (r"\bmv\s+", "Spostamento/rinominazione file"),
    (r"\bchmod\b", "Modifica permessi"),
    (r"\bchown\b", "Modifica proprietario"),
    (r"\bkill\b", "Terminazione processo"),
    (r"\bkillall\b", "Terminazione processi multipli"),
    (r"\bpkill\b", "Terminazione processi per nome"),
    (r"\bsudo\b", "Esecuzione con privilegi elevati"),
    (r"\bsu\b\s", "Cambio utente"),
    (r"\bapt\s+(remove|purge|autoremove)\b", "Rimozione pacchetti"),
    (r"\byum\s+(remove|erase)\b", "Rimozione pacchetti"),
    (r"\bbrew\s+uninstall\b", "Rimozione pacchetti"),
    (r"\bpip\s+uninstall\b", "Disinstallazione pacchetto Python"),
    (r"\bgit\s+push\b", "Push su repository remoto"),
    (r"\bgit\s+reset\s+--hard\b", "Reset distruttivo Git"),
    (r"\bgit\s+clean\b", "Pulizia file Git non tracciati"),
    (r"\bcurl\b.*\|\s*(sudo\s+)?(ba)?sh", "Download ed esecuzione diretta script"),
    (r"\bwget\b.*\|\s*(sudo\s+)?(ba)?sh", "Download ed esecuzione diretta script"),
    (r">\s*/etc/", "Scrittura in /etc"),
    (r"\bsystemctl\s+(stop|restart|disable)\b", "Gestione servizi di sistema"),
    (r"\blaunchctl\b", "Gestione servizi macOS"),
    (r"\bdiskutil\b", "Operazione su disco"),
    (r"\biptables\b", "Modifica regole firewall"),
    (r"\bufw\b", "Modifica firewall"),
]


def check_command_safety(command: str) -> tuple[str, str | None]:
    """
    Check if a command is safe to execute.

    Returns:
        ("blocked", reason)   — command must NOT run
        ("confirm", reason)   — command needs user confirmation
        ("safe", None)        — command is safe to run
    """
    cmd_lower = command.lower().strip()

    for pattern in BLOCKED_COMMANDS:
        if re.search(pattern, cmd_lower):
            return ("blocked", f"Comando bloccato per sicurezza: corrisponde a pattern pericoloso")

    for pattern, description in DANGEROUS_PATTERNS:
        if re.search(pattern, cmd_lower):
            return ("confirm", description)

    return ("safe", None)


# ── Formatted output helpers ─────────────────────────────────────────────────


def print_banner():
    banner = Text()
    banner.append("Shell Agent", style="bold cyan")
    banner.append("  —  ", style="dim")
    banner.append("LMStudio", style="bold magenta")
    console.print(Panel(
        banner,
        subtitle="Scrivi in linguaggio naturale  |  /help per i comandi",
        border_style="cyan",
        padding=(1, 2),
    ))


def print_config_table():
    table = Table(title="Configurazione", show_header=True, border_style="dim")
    table.add_column("Parametro", style="cyan", min_width=20)
    table.add_column("Valore", style="white")
    table.add_row("Endpoint", LMSTUDIO_BASE_URL)
    table.add_row("Modello", MODEL)
    table.add_row("Directory di lavoro", WORKING_DIR)
    table.add_row("Max iterazioni/turno", str(MAX_ITERATIONS))
    table.add_row("Max output/comando", f"{OUTPUT_CAP} chars")
    table.add_row("Max messaggi history", str(MAX_HISTORY))
    console.print(table)
    console.print()


def print_help():
    table = Table(title="Comandi disponibili", show_header=True, border_style="dim")
    table.add_column("Comando", style="yellow", min_width=18)
    table.add_column("Descrizione", style="white")
    table.add_row("/help", "Mostra questo menu")
    table.add_row("/clear", "Azzera la cronologia della conversazione")
    table.add_row("/cwd <path>", "Cambia la directory di lavoro")
    table.add_row("/config", "Mostra la configurazione attuale")
    table.add_row("/exit", "Esci dall'applicazione")
    console.print(table)


def print_command_result(command: str, outcome: dict, step: int):
    """Print a formatted table with the command result."""
    exit_code = outcome["exit_code"]
    success = exit_code == 0
    status_style = "bold green" if success else "bold red"
    status_text = "OK" if success else "ERRORE"

    table = Table(
        title=f"Step {step}",
        show_header=True,
        border_style="green" if success else "red",
        title_style=status_style,
        min_width=60,
    )
    table.add_column("Campo", style="cyan", min_width=12, no_wrap=True)
    table.add_column("Dettaglio", style="white", overflow="fold")

    table.add_row("Comando", f"[bold]{command}[/bold]")
    table.add_row("Stato", f"[{status_style}]{status_text} (exit {exit_code})[/{status_style}]")

    stdout = outcome["stdout"].strip()
    stderr = outcome["stderr"].strip()

    if stdout:
        # Limit preview lines for readability
        lines = stdout.splitlines()
        if len(lines) > 25:
            preview = "\n".join(lines[:25]) + f"\n... ({len(lines) - 25} righe omesse)"
        else:
            preview = stdout
        table.add_row("Output", preview)

    if stderr:
        lines = stderr.splitlines()
        if len(lines) > 15:
            preview = "\n".join(lines[:15]) + f"\n... ({len(lines) - 15} righe omesse)"
        else:
            preview = stderr
        table.add_row("Stderr", f"[red]{preview}[/red]")

    console.print(table)
    console.print()


# ── Tool definitions (sent to the LLM) ───────────────────────────────────────

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "run_command",
            "description": (
                "Execute a shell command on the local system and return its "
                "stdout, stderr, and exit code. "
                "Use this to explore the filesystem, run programs, install "
                "packages, manage files, etc."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute (passed to /bin/sh -c).",
                    },
                    "working_dir": {
                        "type": "string",
                        "description": (
                            "Directory to run the command in. "
                            "Defaults to the agent working directory if omitted."
                        ),
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Max seconds to wait (default 30, max 300).",
                    },
                },
                "required": ["command"],
            },
        },
    }
]

# ── System prompt ─────────────────────────────────────────────────────────────


def build_system_prompt(working_dir: str) -> str:
    return f"""\
You are a helpful shell assistant running on macOS/Linux.
The user will describe what they want to do in natural language.
Your job is to figure out the right shell commands, execute them with the
`run_command` tool, inspect the output, and keep running more commands if
needed until the task is complete.

Rules:
- Always prefer safe, non-destructive commands.
- Before deleting files or making irreversible changes, explain what you
  plan to do and why. The system will ask the user for confirmation.
- If a command fails, read the error output and try to fix the issue.
- After all commands finish, give a clear, concise summary of what happened.
- Current working directory: {working_dir}
- Do NOT wrap commands in markdown code blocks; just use the tool.
- You have a maximum of {MAX_ITERATIONS} tool calls per turn; plan efficiently.
"""


# ── Tool execution ────────────────────────────────────────────────────────────


def run_command(command: str, working_dir: str | None = None, timeout: int = 30) -> dict:
    """Execute *command* in a subprocess and return a result dict."""
    cwd = working_dir or WORKING_DIR
    timeout = max(1, min(timeout, 300))

    try:
        result = subprocess.run(
            command,
            shell=True,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout = result.stdout[:OUTPUT_CAP]
        stderr = result.stderr[:OUTPUT_CAP]
        if result.stdout and len(result.stdout) > OUTPUT_CAP:
            stdout += f"\n[... output truncated at {OUTPUT_CAP} chars ...]"
        if result.stderr and len(result.stderr) > OUTPUT_CAP:
            stderr += f"\n[... stderr truncated at {OUTPUT_CAP} chars ...]"

        return {
            "exit_code": result.returncode,
            "stdout": stdout,
            "stderr": stderr,
        }
    except subprocess.TimeoutExpired:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Command timed out after {timeout} seconds.",
        }
    except Exception as exc:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": str(exc),
        }


def dispatch_tool(name: str, arguments: str, step: int) -> str | None:
    """
    Parse arguments, run safety checks, execute tool, show results.
    Returns JSON result string, or None if the user blocked execution.
    """
    try:
        args = json.loads(arguments)
    except json.JSONDecodeError as exc:
        error = json.dumps({"error": f"Invalid JSON arguments: {exc}"})
        console.print(f"  [red]Errore parsing argomenti: {exc}[/red]")
        return error

    if name != "run_command":
        error = json.dumps({"error": f"Unknown tool: {name}"})
        console.print(f"  [red]Tool sconosciuto: {name}[/red]")
        return error

    command = args["command"]
    wdir = args.get("working_dir")
    timeout = args.get("timeout", 30)

    # ── Security check ───────────────────────────────────────────────
    safety, reason = check_command_safety(command)

    if safety == "blocked":
        console.print(Panel(
            f"[bold red]BLOCCATO[/bold red]: {reason}\n"
            f"Comando: [dim]{command}[/dim]",
            title="Sicurezza",
            border_style="red",
        ))
        return json.dumps({
            "exit_code": -1,
            "stdout": "",
            "stderr": f"BLOCKED by safety filter: {reason}. "
                       "This command is not allowed. Use a safer alternative.",
        })

    if safety == "confirm":
        console.print()
        console.print(Panel(
            f"[bold yellow]Richiesta conferma[/bold yellow]: {reason}\n"
            f"Comando: [bold]{command}[/bold]",
            title="Sicurezza",
            border_style="yellow",
        ))
        try:
            approved = Confirm.ask("  Vuoi eseguire questo comando?", default=False)
        except (EOFError, KeyboardInterrupt):
            approved = False

        if not approved:
            console.print("  [dim]Comando rifiutato dall'utente.[/dim]")
            return json.dumps({
                "exit_code": -1,
                "stdout": "",
                "stderr": "Command DENIED by user. Do NOT retry this command. "
                          "Ask the user what they would like to do instead.",
            })

    # ── Execute ──────────────────────────────────────────────────────
    with Live(
        Spinner("dots", text=Text(f"  Esecuzione: {command[:80]}...", style="dim")),
        console=console,
        transient=True,
    ):
        outcome = run_command(command, wdir, timeout)

    print_command_result(command, outcome, step)
    return json.dumps(outcome)


# ── History management ────────────────────────────────────────────────────────


def trim_history(history: list[dict]) -> list[dict]:
    """
    Keep history within MAX_HISTORY messages.
    Removes oldest user/assistant/tool turns while keeping
    the most recent context intact.
    """
    if len(history) <= MAX_HISTORY:
        return history

    # Keep the last MAX_HISTORY messages
    trimmed = history[-MAX_HISTORY:]

    # Make sure we don't start with a dangling tool result
    while trimmed and trimmed[0].get("role") == "tool":
        trimmed.pop(0)

    return trimmed


# ── Agentic loop ──────────────────────────────────────────────────────────────


def run_agent(client: OpenAI, user_message: str, history: list[dict], working_dir: str) -> str:
    """
    Run one user turn through the agentic tool-use loop.
    Mutates *history* in-place; returns the final assistant text reply.
    """
    history.append({"role": "user", "content": user_message})

    step = 0

    while True:
        # ── Iteration guard ──────────────────────────────────────────
        if step >= MAX_ITERATIONS:
            console.print(Panel(
                f"[yellow]Raggiunto il limite di {MAX_ITERATIONS} iterazioni per questo turno.[/yellow]\n"
                "L'agente si ferma per sicurezza. Puoi continuare con un nuovo prompt.",
                title="Limite iterazioni",
                border_style="yellow",
            ))
            history.append({
                "role": "user",
                "content": (
                    f"You have reached the maximum of {MAX_ITERATIONS} tool calls for this turn. "
                    "Summarize what you have done so far and what remains."
                ),
            })
            # One last call without tools to get a summary
            response = client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "system", "content": build_system_prompt(working_dir)}] + history,
            )
            msg = response.choices[0].message
            history.append(msg.model_dump(exclude_unset=True))
            return msg.content or "(nessuna risposta)"

        # ── LLM call ────────────────────────────────────────────────
        with Live(
            Spinner("dots", text=Text("  Thinking...", style="dim italic")),
            console=console,
            transient=True,
        ):
            response = client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "system", "content": build_system_prompt(working_dir)}] + history,
                tools=TOOLS,
                tool_choice="auto",
            )

        message = response.choices[0].message
        history.append(message.model_dump(exclude_unset=True))

        # ── No tool calls → final text answer ───────────────────────
        if not message.tool_calls:
            # Trim history to keep context manageable
            history[:] = trim_history(history)
            return message.content or ""

        # ── Execute requested tool calls ─────────────────────────────
        for tc in message.tool_calls:
            step += 1

            console.print(Rule(
                f"[bold cyan]Tool call #{step}[/bold cyan]: {tc.function.name}",
                style="dim",
            ))

            tool_result = dispatch_tool(tc.function.name, tc.function.arguments, step)

            if tool_result is None:
                tool_result = json.dumps({
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": "Execution cancelled.",
                })

            history.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": tool_result,
            })


# ── Interactive REPL ──────────────────────────────────────────────────────────


def repl():
    global WORKING_DIR

    client = OpenAI(base_url=LMSTUDIO_BASE_URL, api_key=LMSTUDIO_API_KEY)

    # Connectivity check
    console.print()
    with Live(
        Spinner("dots", text=Text("  Connessione a LMStudio...", style="dim")),
        console=console,
        transient=True,
    ):
        try:
            models = client.models.list()
        except Exception as exc:
            console.print(Panel(
                f"[bold red]Impossibile raggiungere LMStudio[/bold red]\n"
                f"Endpoint: {LMSTUDIO_BASE_URL}\n"
                f"Errore: {exc}\n\n"
                "Assicurati che LMStudio sia avviato con il Local Server attivo.",
                title="Errore connessione",
                border_style="red",
            ))
            sys.exit(1)

    console.print()
    print_banner()
    console.print()
    print_config_table()

    history: list[dict] = []

    while True:
        try:
            console.print()
            user_input = Prompt.ask("[bold green]you[/bold green]").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Bye![/dim]")
            break

        if not user_input:
            continue

        # ── Built-in commands ────────────────────────────────────────
        cmd_lower = user_input.lower()

        if cmd_lower in ("/exit", "/quit", "exit", "quit"):
            console.print("[dim]Bye![/dim]")
            break

        if cmd_lower == "/help":
            print_help()
            continue

        if cmd_lower == "/clear":
            history.clear()
            console.print("[dim]Cronologia conversazione azzerata.[/dim]")
            continue

        if cmd_lower == "/config":
            print_config_table()
            continue

        if cmd_lower.startswith("/cwd "):
            new_cwd = user_input[5:].strip()
            expanded = os.path.expanduser(new_cwd)
            if os.path.isdir(expanded):
                WORKING_DIR = expanded
                console.print(f"[dim]Directory di lavoro: {WORKING_DIR}[/dim]")
            else:
                console.print(f"[red]Directory non trovata: {expanded}[/red]")
            continue

        # ── Run the agent ────────────────────────────────────────────
        try:
            console.print()
            t0 = time.time()
            reply = run_agent(client, user_input, history, WORKING_DIR)
            elapsed = time.time() - t0

            console.print(Panel(
                Markdown(reply),
                title="[bold blue]Agent[/bold blue]",
                subtitle=f"[dim]{elapsed:.1f}s[/dim]",
                border_style="blue",
                padding=(1, 2),
            ))
        except KeyboardInterrupt:
            console.print("\n[dim][interrupted][/dim]")
        except Exception as exc:
            console.print(Panel(
                f"[bold red]Errore[/bold red]: {exc}",
                title="Errore",
                border_style="red",
            ))


if __name__ == "__main__":
    repl()
