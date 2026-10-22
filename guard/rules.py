"""Layer A of the guard: fast, explainable regex rules. Each rule has a label and a weight (0-1)."""
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    """One detection rule: a name, the attack type it indicates, how strong the evidence is, and the pattern."""
    name: str
    label: str
    weight: float
    pattern: re.Pattern


def _r(name: str, label: str, weight: float, pat: str) -> Rule:
    """Build a Rule from a regex string (case-insensitive; '.' also matches line breaks)."""
    return Rule(name, label, weight, re.compile(pat, re.I | re.S))


# Words that name "instructions" in different ways; reused by the ignore_previous rule below.
_INSTR = r"(instructions?|rules?|prompts?|directions?|directives?|guidelines?|context)"

RULES = [
    # ======== dangerous_command: file paths and shell commands ========
    # "../" or its URL-encoded forms: trying to climb out of the allowed folder.
    _r("path_traversal", "dangerous_command", 0.95, r"\.\.[\\/]|%2e%2e|\.\.%2f"),
    # A Windows drive path such as C:\ or D:/ (the sandbox only uses relative paths).
    _r("absolute_windows_path", "dangerous_command", 0.85, r"\b[a-z]:[\\/]"),
    # Sensitive Unix locations: /etc/passwd, ~/.ssh, /root/, shell history.
    _r("unix_sensitive_path", "dangerous_command", 0.95,
       r"/etc/(passwd|shadow|sudoers|hosts)|/proc/self|~/\.ssh|(^|[\s'\"=(])/(root|home)/|\.bash_history"),
    # Sensitive Windows locations: system32, win.ini, the SAM password database.
    _r("windows_system_path", "dangerous_command", 0.9, r"system32|win\.ini|\\windows\\|config[\\/]sam\b"),
    # Files that normally hold secrets: .env, private keys, credentials files.
    _r("secret_file", "dangerous_command", 0.9,
       r"(^|[\\/\s'\"=(])\.env\b|id_rsa|\.pem\b|credentials\.json|\.aws[\\/]|[\\/]credentials\b|\bsecrets?\.(json|ya?ml|txt)\b"),
    # Commands that delete data or wipe disks (rm -rf, del /f, format C:, mkfs, dd).
    _r("destructive_shell", "dangerous_command", 0.95,
       r"\brm\s+-[a-z]*r[a-z]*f|\bdel\s+/[fqs]|\brmdir\s+/s|\bformat\s+[a-z]:|\bmkfs|\bdd\s+if=|remove-item\s+-recurse"),
    # Download-and-run: "curl ... | bash", PowerShell iex, Invoke-Expression.
    _r("download_and_exec", "dangerous_command", 0.95,
       r"\b(curl|wget|iwr|invoke-webrequest)\b[^|\n]*\|\s*(sh|bash|iex|powershell)\b|\biex\s*\(|invoke-expression"),
    # Reverse-shell tools: netcat, /dev/tcp.
    _r("reverse_shell", "dangerous_command", 0.95, r"\bnc\s+-e\b|/dev/tcp/|\bnetcat\b"),
    # Starting a shell with arguments, or using sudo (weaker evidence on its own).
    _r("shell_invocation", "dangerous_command", 0.7,
       r"\bpowershell(\.exe)?\s+-|\bcmd(\.exe)?\s+/c\b|\b(bash|sh)\s+-[ci]\b|\bsudo\b"),
    # Python calls that run arbitrary code or commands.
    _r("code_exec", "dangerous_command", 0.75, r"os\.system\(|subprocess\.|\beval\(|\bexec\("),
    # Changing permissions, the registry, scheduled tasks or the firewall; killing processes.
    _r("persistence_or_perms", "dangerous_command", 0.85,
       r"\bchmod\s+[0-7]*7[0-7]*\b|\breg\s+(add|delete)\b|\bschtasks\s+/create|\bnetsh\s+advfirewall|\btaskkill\b"),
    # Chaining a second command after ';' or '&&' (cat, del, curl, ...).
    _r("shell_chaining", "dangerous_command", 0.8, r"(^|\s)(;|&&)\s*(cat|type|del|rm|curl|wget|powershell)\b"),
    # Encoded or obfuscated payloads (PowerShell -enc, base64 -d).
    _r("encoded_payload", "dangerous_command", 0.7, r"\s-enc\s+[a-z0-9+/=]{20,}|base64\s+(-d|--decode)"),

    # ======== prompt_injection: text that tries to take control of the AI ========
    # "Ignore / disregard / forget ... previous instructions": the classic override.
    _r("ignore_previous", "prompt_injection", 0.95,
       rf"\b(ignore|disregard|forget|override|discard)\b\s+(all\s+|any\s+|the\s+|your\s+|my\s+)*"
       rf"(previous|prior|above|earlier|preceding|original|existing|current)\s+{_INSTR}"),
    # "ignore previous policy text", "earlier ... is obsolete": overrides of earlier content, not only of "instructions"
    _r("ignore_earlier_content", "prompt_injection", 0.8,
       r"\b(ignore|disregard)\b\s+(all\s+|any\s+|the\s+)*(previous|prior|earlier|above)\s+\w+(\s+\w+)?\s+(text|content|policy|policies|documents?|information)"),
    # "(for AI agents only)": content addressed to the AI instead of the human reader.
    _r("for_ai_only", "prompt_injection", 0.8, r"\(?for\s+(ai|llm|assistants?|agents?|ai\s+agents?|models?)\s+only\)?"),
    # "Forget everything above / what you were told".
    _r("forget_everything", "prompt_injection", 0.9,
       r"\bforget\s+(everything|all|what)\b.{0,30}(above|before|told|instructions?|rules?)"),
    # Jailbreak role changes: "you are now ...", DAN, developer mode, unrestricted mode.
    _r("role_reset", "prompt_injection", 0.85,
       r"\byou\s+are\s+now\s+(a|an|in|the)\b|\bdo\s+anything\s+now\b|\bDAN\b|developer\s+mode|jailbreak(ed)?\s+mode|unrestricted\s+mode"),
    # Asking the AI to reveal its hidden system prompt or configuration.
    _r("reveal_system_prompt", "prompt_injection", 0.9,
       r"\b(reveal|show|print|repeat|output|display|leak)\b.{0,20}\b(your|the)\s+(system|hidden|initial|secret)\s+(prompt|instructions?|configuration|setup)"),
    # "New instructions:" / "New task:" headings that replace the real task.
    _r("new_instructions", "prompt_injection", 0.8, r"\bnew\s+(system\s+)?(instructions?|prompt|task)\s*[:.]"),
    # Fake chat-template markers (<system>, [INST], <|im_start|>) used to impersonate the system.
    _r("chat_template_tokens", "prompt_injection", 0.9, r"</?system>|\[/?INST\]|<\|im_(start|end)\|>|<\|system\|>"),
    # "Do not mention this note / these instructions": hiding the attack from the reader.
    _r("conceal_instruction", "prompt_injection", 0.85,
       r"\bdo\s+not\s+(mention|reveal|disclose|share|repeat)\s+(this|these|the)\s+(note|notes|instructions?|message|text|rules?)\b"),
    # "Do not tell the user", "without telling the user".
    _r("hide_from_user", "prompt_injection", 0.85,
       r"\bdo\s+not\s+(tell|inform|mention|alert|warn)\b.{0,25}\buser\b|\bwithout\s+(telling|informing|alerting)\s+(the\s+)?user"),
    # Asking the AI to switch off its safety rules or filters.
    _r("disable_safety", "prompt_injection", 0.85,
       r"\b(override|bypass|disable|skip|turn\s+off|lifted)\b.{0,25}\b(safety|security|guardrails?|restrictions?|filters?|guidelines?|safety\s+checks?)"),
    # Text speaking directly to the AI: "Note to the assistant", "Attention LLM", "IMPORTANT: AI ...".
    _r("addresses_the_ai", "prompt_injection", 0.8,
       r"\b(attention|note\s+to|message\s+for|hidden\s+instruction\s+for|important[:!]?)\s*,?\s*(the\s+)?(ai|assistant|llm|model|agent)\b"),
    # Trying to plant a lasting instruction in the AI's memory ("remember this permanently").
    _r("memory_poisoning", "prompt_injection", 0.8,
       r"\b(remember|store|save|add)\b.{0,30}\b(this|it)?\b.{0,20}\b(permanently|forever|long[- ]term\s+memory|for\s+all\s+future|in\s+memory)\b"),
    # Standing orders: "from now on ... always / never / ignore ...".
    _r("persistent_rule", "prompt_injection", 0.75,
       r"\b(from\s+now\s+on|for\s+all\s+future\s+conversations?|permanently)\b.{0,60}\b(ignore|always|never|forward|trust)\b"),

    # ======== prompt_injection: MCP tool poisoning (hidden instructions in tool definitions) ========
    # "include the file contents in the 'notes' parameter": a tool asking for data to be passed in an argument.
    _r("tool_data_in_param", "prompt_injection", 0.85,
       r"\b(include|pass|put|add|place|send|provide|append|supply)\b.{0,70}"
       r"\b(contents?|text|history|listing|passwords?|keys?|tokens?|credentials?|results?|conversation|messages?|data)\b.{0,70}"
       r"\b(in|into|as|via|along\s+as)\b.{0,25}(['\"`]\w+['\"`]|\bparameters?\b|\barguments?\b|\bfields?\b)"),
    # "Before using this tool, first ...": a hidden pre-step a tool demands.
    _r("tool_precondition", "prompt_injection", 0.7,
       r"\b(before|prior\s+to)\s+(using|calling|invoking)\b.{0,15}\b(this|the)\s+tool\b|\bmust\s+be\s+called\s+(before|first)\b"
       r"|\balways\s+(call|use)\s+this\s+tool\s+first\b|\bprerequisite\b"),
    # A hidden <IMPORTANT> / <secret> block inside a description.
    _r("tool_hidden_tag", "prompt_injection", 0.85, r"<\s*(important|critical|secret|hidden|instructions?)\s*>"),
    # A tool claiming to replace or outrank the other tools.
    _r("tool_supersedes", "prompt_injection", 0.8,
       r"\b(use|prefer)\b.{0,25}\b(this|me)\b.{0,25}\b(instead\s+of|over)\b.{0,40}\b(other|any|the)\b.{0,25}\btools?\b"
       r"|\bsupersedes?\b|\binstead\s+of\s+the\s+other\b"),
    # "Never tell the user", "must stay hidden": instructions to keep the trick secret.
    _r("tool_keep_secret", "prompt_injection", 0.85,
       r"\bnever\s+(tell|reveal|mention|disclose)\b.{0,30}\b(user|this|requirement)\b|\bmust\s+stay\s+hidden\b"
       r"|\bhidden\s+from\s+the\s+user\b|\buser\s+does\s+not\s+need\s+to\s+know\b"),
    # "Silently send / forward / read ...": acting without the user noticing.
    _r("silent_action", "prompt_injection", 0.85, r"\bsilently\b.{0,40}\b(call|send|forward|read|copy|upload)\b"),
    # Claiming special powers: "system override", "you now have administrator rights".
    _r("claims_admin_rights", "prompt_injection", 0.85,
       r"\bsystem\s+override\b|\badministrator\s+rights\b|\byou\s+now\s+have\s+(admin|administrator|root)\b"),

    # ======== malicious_intent: stealing and sending data out ========
    # Plain data-theft vocabulary: exfiltrate, steal, smuggle, harvest.
    _r("exfil_words", "malicious_intent", 0.9, r"\b(exfiltrat\w*|steal|smuggle|harvest)\b"),
    # Sending something to a URL, webhook or remote server. "email" only counts as a verb
    # ("email the files to ..."), not the noun in "Support email: a@b.com".
    _r("send_to_external", "malicious_intent", 0.85,
       r"\b(send|post|upload|forward|transmit|ship|leak|publish|email\s+(?:the|all|me|it|them|this|these|those|my|your|a|an|copies|contents?|files?))\b"
       r".{0,80}(https?://|webhook|pastebin|remote\s+(server|box)|external\s+(server|url))"),
    # Sending something to an email address. Weaker evidence: "send your resume to careers@x.com" is routine in documents.
    _r("send_to_email_address", "malicious_intent", 0.7,
       r"\b(send|post|upload|forward|transmit|ship|leak|publish|email\s+(?:the|all|me|it|them|this|these|those|my|your|a|an|copies|contents?|files?))\b"
       r".{0,80}@[\w.-]+\.\w+"),
    # Asking to list, find or dump passwords, keys or tokens "stored" or "on this machine".
    _r("credential_harvest", "malicious_intent", 0.9,
       r"\b(dump|list|find|show|give\s+me|extract|print|collect|gather|locate|retrieve)\b.{0,40}"
       r"\b(passwords?|credentials?|api[\s_-]?keys?|secret\s+keys?|private\s+keys?|tokens?|logins?)\b"
       r".{0,40}\b(all|every|any|stored|saved|machine|system|laptop|computer|disk)\b"),
    # A Markdown image whose URL carries data in its query string: leaks data when the page renders.
    _r("markdown_image_exfil", "malicious_intent", 0.85, r"!\[[^\]]*\]\(https?://[^)\s]*\?[^)\s]*=[^)\s]*\)"),
    # "Read every file on the system".
    _r("read_everything", "malicious_intent", 0.8,
       r"\b(read|copy|collect|list)\b\s+(every|all)\s+(the\s+)?(files?|documents?)\b.{0,40}\b(system|computer|disk|drive|machine)\b"),
]


def scan(text: str) -> list[tuple[Rule, str]]:
    """Return (rule, matched_snippet) for each rule that fires on the text."""
    hits = []
    for rule in RULES:
        m = rule.pattern.search(text)
        if m:
            hits.append((rule, m.group(0)[:80]))  # keep a short snippet of what matched
    return hits
