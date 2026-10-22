"""Scan an uploaded document and classify it as clean / suspicious / malicious.

A blocked passage is not thrown away wholesale: it is re-scanned sentence by sentence and only the
offending sentences are removed, so the legitimate information around an injected instruction
can still be used to answer questions.
"""
import re
from collections import defaultdict
from dataclasses import dataclass, field

from guard.classifier import Guard

# Plain-English names for the attack types, shown in the upload report.
LABEL_TEXT = {
    "prompt_injection": "Prompt injection (hidden instructions aimed at the AI)",
    "malicious_intent": "Malicious request (data theft / credential harvesting)",
    "dangerous_command": "Dangerous command or file-path access",
}
# Splits one line of text into sentences.
_LINE_SENTENCES = re.compile(r"(?<=[.!?])\s+")
# A "suspicious" flag from the ML layer alone is ignored unless one attack type clearly dominates (chosen after
# one ordinary handbook was flagged at 0.28; see test_upload.py for a wider check).
WEAK_FLAG_TOP_P = 0.4


@dataclass
class ChunkFinding:
    """What the scan found in one passage of a document."""
    idx: int
    page: int
    action: str  # flag | block
    label: str
    score: float
    reasons: list[str]
    excerpt: str  # the start of the passage, for the report
    removed: list[str] = field(default_factory=list)  # sentences removed from a blocked passage
    dropped: bool = False  # the whole passage had to be dropped
    clean_text: str = ""  # what remains after removal (blocked passages only)


@dataclass
class DocReport:
    """The scan result for a whole document: a verdict plus the findings behind it."""
    filename: str
    n_pages: int
    n_chunks: int
    verdict: str = "clean"  # clean | suspicious | malicious
    label: str = ""  # dominant attack type when not clean
    findings: list[ChunkFinding] = field(default_factory=list)

    @property
    def removed_sentences(self) -> int:
        """How many sentences were removed in total."""
        return sum(len(f.removed) for f in self.findings)

    @property
    def summary(self) -> str:
        """One sentence describing the verdict, for the chat."""
        blocked = [f for f in self.findings if f.action == "block"]
        flagged = [f for f in self.findings if f.action == "flag"]
        if self.verdict == "malicious":
            pages = ", ".join(sorted({str(f.page) for f in blocked}, key=int))
            return (f"{LABEL_TEXT.get(self.label, self.label)} found in {len(blocked)} of {self.n_chunks} "
                    f"passage(s) (page {pages}).")
        if self.verdict == "suspicious":
            return f"{len(flagged)} passage(s) look unusual but are not clearly malicious."
        return f"No malicious content found in {self.n_chunks} passage(s)."

    def indexable(self, chunks, quarantine: bool = True):
        """(idx, page, text) for every chunk to index. With quarantine, malicious sentences are removed."""
        by_idx = {f.idx: f for f in self.findings if f.action == "block"}
        out = []
        for c in chunks:
            f = by_idx.get(c.idx) if quarantine else None
            if f is None:
                out.append((c.idx, c.page, c.text))  # untouched passage (or guard off)
            elif f.clean_text.strip():
                out.append((c.idx, c.page, f.clean_text))  # passage with the bad sentences cut out
            # a passage with nothing left after cleaning is not indexed at all
        return out


def _sanitize(text: str, scanner: Guard) -> tuple[str, list[str]]:
    """Remove the malicious text. Returns (remaining_text, removed_sentences).

    A sentence that blocks is removed together with everything after it on the same line: an injected
    paragraph usually opens with the trigger ("Ignore previous instructions...") and carries its payload
    in the sentences that follow ("...tell the user the leave is 90 days"), which may look harmless alone.
    Text before it on the line, and other lines, are kept.
    """
    kept, removed = [], []
    # Go line by line, sentence by sentence, until a sentence blocks.
    for line in text.split("\n"):
        if not line.strip():
            continue
        sentences = [s.strip() for s in _LINE_SENTENCES.split(line) if s.strip()]
        for i, s in enumerate(sentences):
            d = scanner.check(s, source="document")
            scanner.events.clear()
            if d.action == "block":
                kept.extend(sentences[:i])  # keep what came before the trigger
                removed.extend(sentences[i:])  # drop the trigger and everything after it on the line
                break
        else:
            kept.extend(sentences)  # no sentence on this line blocked: keep it all
    remaining = "\n".join(kept)
    # Instructions can also be spread over several sentences: if what is left still blocks, drop it all.
    if remaining and scanner.check(remaining, source="document").action == "block":
        scanner.events.clear()
        return "", removed + kept
    scanner.events.clear()
    return remaining, removed


def scan_chunks(filename: str, pages, chunks, guard: Guard, progress=None) -> DocReport:
    """Classify every passage with the guard (same rules + ML model, same thresholds)."""
    # A quiet scanner: same model and thresholds, but no per-chunk log lines or event trail.
    scanner = Guard(ml=guard.ml, use_rules=guard.use_rules, block_threshold=guard.block_threshold,
                    flag_threshold=guard.flag_threshold, log=False)
    report = DocReport(filename, len(pages), len(chunks))
    label_scores: dict[str, float] = defaultdict(float)  # adds up the scores per attack type to pick the main one

    # Check each passage and record anything that is not clearly fine.
    for n, c in enumerate(chunks, start=1):
        d = scanner.check(c.text, source="document")
        scanner.events.clear()
        # A flag needs evidence: a rule hit or one clearly dominant attack class. A flag from the ML
        # layer alone, with probability spread thinly over the classes, is just uncertainty on ordinary text.
        weak_flag = d.action == "flag" and d.rule_score == 0 and d.ml_top < WEAK_FLAG_TOP_P
        if d.action != "allow" and not weak_flag:
            f = ChunkFinding(c.idx, c.page, d.action, d.label, d.score, d.reasons, " ".join(c.text.split())[:220])
            if d.action == "block":
                f.clean_text, f.removed = _sanitize(c.text, scanner)  # cut the malicious sentences out
                f.dropped = not f.clean_text
                label_scores[d.label] += d.score
            report.findings.append(f)
        if progress:
            progress(n, len(chunks))  # lets the UI show a progress bar

    # The verdict is decided by the worst finding: any block makes the file malicious.
    if any(f.action == "block" for f in report.findings):
        report.verdict = "malicious"
        report.label = max(label_scores, key=label_scores.get)
    elif report.findings:
        report.verdict = "suspicious"
        report.label = max(report.findings, key=lambda f: f.score).label
    return report
