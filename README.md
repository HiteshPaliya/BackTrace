# Polyglot Cross-File Source Code Security Reviewer

An offensive-minded, automated source code security review system designed to identify high-impact vulnerabilities (e.g., Remote Code Execution, SQL/NoSQL Injection, Authentication & Authorization Bypasses, SSRF, Path Traversal, and Hardcoded Secrets) through automated attack surface mapping, deterministic cross-file taint reachability, and agentic LLM reasoning.

---

## Key Features

- **Polyglot Tree-sitter Parsing:** Multi-language symbol extraction, import mapping, and abstract syntax tree (AST) traversal across JavaScript, TypeScript, Python, and more.
- **Persistent Code Property Graph (CPG):** Decoupled graph database stored in SQLite (`.audit/audit.db`) capturing files, symbols, endpoints, candidate sinks, and cross-file data/call flows.
- **Multi-Dimensional Scope Classification:** Automatically classifies files by execution domain (server, client, worker), runtime role, and environment, filtering out test fixtures, docs, and build outputs while shallowly harvesting vendor signatures.
- **Pluggable Scanner Adapters:** Native integration with leading static analysis and secret detection tools:
  - **OWASP Noir:** Endpoint and attack surface discovery.
  - **Semgrep:** Pattern-based sink detection and security rules.
  - **TruffleHog:** High-entropy secret and credential harvesting.
  - *Graceful degradation:* If an external tool is missing from the host environment, the reviewer logs a warning and proceeds with AST and semantic heuristics.
- **Framework Semantic Resolvers:** Specialized framework analyzers (e.g., Express.js) that map chained route definitions, HTTP verb dispatchers, and middleware authorization boundaries.
- **Deterministic Reachability & Cycle Pruning:** Graph search with bounded hop limits and cycle termination to compute high-confidence taint paths from untrusted sources to sensitive sinks before engaging LLMs.
- **Dual-Mode LLM Reasoning & Evidence Gate:**
  - Evaluates sanitization routines, auth boundaries, and reachability.
  - Employs strict evidence sufficiency gates—findings require deterministic proof or defensible exploit rationale.
  - Dual topology: Supports cloud-based Gemini models as well as offline/local LLM backends via Ollama.
  - **Zero Private Chain-of-Thought Leakage:** Internal scratchpads remain strictly ephemeral; only curated evidence, structured traces, and public verdicts are recorded.
- **Incremental & Resumable Auditing:**
  - **Engine Fingerprinting:** Hashes scanner configuration, tool versions, rulesets, and model IDs to safely reuse unaffected dossiers.
  - **Git Diff Engine:** Fast incremental scans evaluating working tree changes and untracked files.
  - **Resumable State:** Interrupted or long-running scans can be resumed seamlessly via `.audit/audit.db` and thread-safe `.audit/events.jsonl` logs.
- **Standardized Multi-Format Reporting:**
  - **SARIF 2.1.0:** Fully compliant with GitHub Advanced Security and IDE code scanners, embedding multi-hop code flows.
  - **Interactive Markdown:** Executive summaries, CVSS/CWE mappings, vulnerability theories, and reproduction cURL blueprints.
  - **Graph JSON:** Full serializable graph export for visualization and downstream security pipeline ingestion.

---

## Architecture Flow

```
                      +---------------------------------------+
                      |               Target Repo             |
                      +---------------------------------------+
                                          |
                      +---------------------------------------+
                      |         Workspace & Ingestion         |
                      |  - Path canonicalization              |
                      |  - Multidimensional scope classifier  |
                      |  - Vendor signature harvester         |
                      +---------------------------------------+
                                          |
        +---------------------------------+---------------------------------+
        |                                 |                                 |
        v                                 v                                 v
+-----------------+              +------------------+             +-------------------+
|  AST Indexing   |              |  Tool Adapters   |             | Framework Resolv. |
|  - Tree-sitter  |              |  - Semgrep       |             | - Express routes  |
|  - Symbols/Defs |              |  - Noir          |             | - Middleware auth |
|  - Call graphs  |              |  - TruffleHog    |             +-------------------+
+-----------------+              +------------------+                       |
        |                                 |                                 |
        +---------------------------------+---------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |      Code Property Graph (CPG)        |
                      |  Persistent SQLite (.audit/audit.db)  |
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |    Taint Reachability & Triage        |
                      |  - Cycle pruning & bounded hops       |
                      |  - Priority scoring & deduplication   |
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |   Evidence Gate & Agentic Reasoning   |
                      |  - LLM Router (Gemini / Ollama)       |
                      |  - Sanitizer & contract flow analysis |
                      |  - Reproduction blueprint synthesis   |
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |         Reporting & Export            |
                      |  - Markdown (.md)                     |
                      |  - SARIF 2.1.0 (.sarif)               |
                      |  - Graph JSON (.json)                 |
                      +---------------------------------------+
```

---

## Getting Started

### Prerequisites

- **Python:** Version 3.11 or later
- **Optional Static Tools:**
  - [Semgrep](https://semgrep.dev/) (for sink detection)
  - [OWASP Noir](https://github.com/owasp-noir/noir) (for endpoint discovery)
  - [TruffleHog](https://github.com/trufflesecurity/trufflehog) (for secret discovery)

### Installation

Clone the repository and install dependencies in editable mode:

```bash
git clone https://github.com/your-org/source-code-reviewer.git
cd source-code-reviewer

# Create and activate virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install package with development dependencies
pip install -e ".[dev]"
```

---

## Configuration

Set up environment variables depending on your desired LLM backend:

### Cloud LLM (Google Gemini)
```bash
export GEMINI_API_KEY="your-gemini-api-key"
```

### Local / Offline LLM (Ollama)
Ensure Ollama is running locally:
```bash
export OLLAMA_HOST="http://localhost:11434"
export OLLAMA_MODEL="qwen2.5-coder:14b"
```

---

## Usage

The CLI provides four main subcommands: `scan`, `diff`, `report`, and `resume`.

### 1. Full Security Scan (`scan`)

Run a full security review over a codebase:

```bash
# Scan current repository
python -m src.cli scan .

# Scan specific target with custom workers and model
python -m src.cli scan /path/to/target-repo --workers 8 --model gemini-3.8-flash
```

Scan state and SQLite databases are stored under `<target>/.audit/audit.db`.

### 2. Incremental Diff Scan (`diff`)

Analyze changes between the working tree and a Git base reference:

```bash
# Compare current changes against HEAD
python -m src.cli diff . --base HEAD

# Compare against a specific branch or commit
python -m src.cli diff /path/to/target-repo --base origin/main
```

The diff engine automatically identifies modified files and reuses cached dossiers when code and tool fingerprints remain valid.

### 3. Generate Reports (`report`)

Export audited vulnerability dossiers into your preferred format:

```bash
# Export Markdown report to stdout
python -m src.cli report --scan-id <SCAN_ID> --format md

# Export SARIF 2.1.0 for GitHub Security tab integration
python -m src.cli report --scan-id <SCAN_ID> --format sarif --output results.sarif

# Export Code Property Graph in JSON format
python -m src.cli report --scan-id <SCAN_ID> --format graph --output cpg.json
```

### 4. Resume an Interrupted Scan (`resume`)

Resume a paused, timed out, or interrupted scan session without reprocessing already-triaged paths:

```bash
python -m src.cli resume <SCAN_ID> --target /path/to/target-repo
```

---

## Project Structure

```
source-code-reviewer/
├── pyproject.toml         # Build configuration, package metadata, dependencies
├── package.json           # Repository metadata and linting scripts
├── src/
│   ├── cli.py             # Click CLI entrypoint (scan, diff, report, resume)
│   ├── core/              # Scope classification and workspace manager
│   ├── indexer/           # Tree-sitter polyglot AST & symbol parsers
│   ├── adapters/          # Tool adapters (Semgrep, Noir, TruffleHog)
│   ├── frameworks/        # Web framework route & middleware resolvers
│   ├── graph/             # Code Property Graph (CPG) & reachability
│   ├── semantic/          # Sources, sinks, and sanitization detectors
│   ├── triage/            # Priority queue and composite risk scoring
│   ├── agents/            # Verification agents, debate engine, contract flow
│   ├── diff/              # Git diff scanner and incremental fingerprinting
│   ├── storage/           # SQLite database manager and append-only event logger
│   ├── reporting/         # SARIF, Markdown, and Graph JSON exporters
│   └── llm/               # Model routing (Gemini, Ollama)
└── tests/                 # Comprehensive test suite (99+ tests)
```

---

## Development & Testing

### Running Tests

Execute the full test suite with `pytest`:

```bash
pytest
```

Run test suite with coverage report:

```bash
pytest --cov=src --cov-report=term-missing
```

### Linting and Formatting

Code style is enforced via `ruff`:

```bash
# Check for lint errors
ruff check .

# Apply formatting
ruff format .
```

---

## Strict Non-Goals

To maintain a laser focus on high-fidelity security analysis and researcher productivity, this project explicitly avoids:

1. **No Live Attack Execution:** Does not trigger dynamic payloads or HTTP exploits against live targets; provides static reproduction templates for manual researcher verification.
2. **No Weaponized Shellcode Generation:** Does not generate binary exploits or memory corruption payloads.
3. **No Compliance & Style Bloat:** Omits superficial linting and style noise to focus strictly on exploitable security weaknesses.
4. **No Monolithic Prompt Dumps:** Uses structured reachability slices rather than massive whole-repository context stuffing.
5. **No Private Deliberation Persistence:** Ensures all LLM scratchpads remain strictly ephemeral; only public verifiable evidence is stored.

---

## License

This project is licensed under the ISC License. See `package.json` for details.
