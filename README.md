# Shell Agent

An interactive terminal agent that translates natural language into shell commands using a local LLM via [LMStudio](https://lmstudio.ai/).

You describe what you need — the agent figures out the right commands, executes them, reads the output, and keeps going until the task is done.

## Features

- **Natural language interface** — describe tasks in plain text, the agent handles the shell
- **Agentic loop** — the LLM can chain multiple commands, inspect results, and self-correct on errors
- **Safety layer** — destructive commands (rm, kill, sudo, ...) require explicit confirmation; known dangerous patterns (fork bombs, disk wipes, ...) are blocked entirely
- **Structured output** — command results displayed in formatted tables with exit codes, stdout/stderr separation, and step numbering
- **Conversation memory** — multi-turn context with automatic history trimming to stay within the model's context window
- **Zero cloud dependencies** — everything runs locally through LMStudio

## Requirements

- Python 3.10+
- [LMStudio](https://lmstudio.ai/) running with the **Local Server** enabled (default port: 1234)
- A model with **tool/function calling** support loaded in LMStudio (e.g. Qwen 2.5, Mistral, Llama 3.1)

## Installation

```bash
git clone https://github.com/fabriziogaliano/shell-agent.git
cd shell-agent

pip install -r requirements.txt

cp .env.example .env
# Edit .env with your settings
```

## Usage

```bash
python shell_agent.py
```

### Example prompts

```
you> list the 10 largest files in the home directory
you> find all .log files modified in the last 3 days
you> how much RAM is in use right now?
you> show disk usage breakdown by folder in /var
you> create a folder called "backup" and copy all .conf files into it
```

### REPL commands

| Command | Description |
|---|---|
| `/help` | Show available commands |
| `/clear` | Reset conversation history |
| `/cwd <path>` | Change working directory |
| `/config` | Show current configuration |
| `/exit` | Quit |

## Configuration

Copy `.env.example` to `.env` and adjust the values:

| Variable | Default | Description |
|---|---|---|
| `LMSTUDIO_URL` | `http://localhost:1234/v1` | LMStudio API endpoint |
| `LMSTUDIO_API_KEY` | `lm-studio` | API key (any non-empty string works) |
| `LMSTUDIO_MODEL` | `local-model` | Model identifier |
| `SHELL_AGENT_CWD` | `$HOME` | Initial working directory |
| `SHELL_AGENT_OUTPUT_CAP` | `8000` | Max characters captured per command output |
| `SHELL_AGENT_MAX_ITER` | `15` | Max tool calls per turn (safety limit) |
| `SHELL_AGENT_MAX_HISTORY` | `40` | Max messages kept in conversation history |

## Security

The agent enforces three levels of protection:

**Critical commands** — require **double confirmation** before execution:
- Recursive root deletion (`rm -rf /`)
- Disk formatting (`mkfs`, `dd of=/dev/...`)
- Fork bombs
- System halt/reboot/shutdown

**Dangerous commands** — require single confirmation (default: no):
- File deletion and moves (`rm`, `mv`)
- Permission/ownership changes (`chmod`, `chown`)
- Process termination (`kill`, `pkill`)
- Privilege escalation (`sudo`, `su`)
- Package removal (`apt remove`, `pip uninstall`, `brew uninstall`)
- Destructive git operations (`push`, `reset --hard`, `clean`)
- Remote script execution (`curl | sh`)
- Firewall and service management

**All other commands** — require confirmation (default: yes):
- Every command is shown to the user before execution
- Safe commands default to "yes" but can still be rejected

## License

MIT
