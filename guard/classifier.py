"""Combines the rule layer and the ML layer into one allow / flag / block decision."""
import json
import re
import time
from dataclasses import asdict, dataclass, field

import config
from guard import rules
from guard.ml import MLGuard

# A score at or above BLOCK_THRESHOLD is blocked; at or above FLAG_THRESHOLD (but below block) is flagged.
BLOCK_THRESHOLD = 0.80
FLAG_THRESHOLD = 0.50

# Long text (documents, search results) is scored in overlapping windows; the worst window wins.
WINDOW = 500
STRIDE = 350

# Every decision is appended to this file as one JSON line.
LOG_PATH = config.ROOT / "logs" / "guard.jsonl"


@dataclass
class Decision:
    """The guard's verdict on one piece of text."""
    action: str  # allow | flag | block
    label: str  # benign | malicious_intent | prompt_injection | dangerous_command
    score: float  # 0-1: how strongly the text looks like an attack
    source: str  # where the text came from: user_input | tool_call | tool_output | tool_description | document
    reasons: list[str] = field(default_factory=list)  # which rules / model fired
    rule_score: float = 0.0  # strongest rule match
    ml_score: float = 0.0  # 1 - probability of "benign" from the ML model
    ml_top: float = 0.0  # probability of the single most likely attack class (high = one clear attack type)

    @property
    def blocked(self) -> bool:
        return self.action == "block"


def _windows(text: str) -> list[str]:
    """Cut a long text into overlapping windows (a short text is returned as is)."""
    if len(text) <= WINDOW:
        return [text]
    return [text[i : i + WINDOW] for i in range(0, len(text) - WINDOW + STRIDE, STRIDE)]


def _segments(text: str) -> list[str]:
    """Windows plus individual sentences/lines, so one malicious sentence is not
    diluted by the benign text around it (e.g. several search results joined together)."""
    segs = _windows(text)
    parts = [p.strip() for p in re.split(r"(?<=[.!?])\s+|\n+", text) if len(p.strip()) >= 25]
    if len(parts) > 1:
        segs += parts
    return segs


class Guard:
    """The classifier: call check(text, source) to get a Decision."""

    def __init__(self, ml: "MLGuard | None" = "default", use_rules: bool = True,
                 block_threshold: float = BLOCK_THRESHOLD, flag_threshold: float = FLAG_THRESHOLD,
                 log: bool = True):
        # ml="default" loads the saved model; ml=None runs on rules only.
        self.ml = MLGuard.load() if ml == "default" else ml
        self.use_rules = use_rules
        self.block_threshold = block_threshold
        self.flag_threshold = flag_threshold
        self.log = log
        # In-memory trail of (checked_text, Decision), so a UI can show what the guard did.
        self.events: list[tuple[str, Decision]] = []
        # Content the guard withheld from the model while a question was being answered (see guard/wrap.py);
        # a UI collects these to show what was removed. Each entry: origin, source, label, content.
        self.removals: list[dict] = []
        # The user's own latest message, set once per turn (see guard/wrap.py, WRITE_TOOLS): a write tool
        # may only act on a file this message names, so a hidden instruction elsewhere cannot trigger one.
        self.current_question: str = ""

    def _score_window(self, text: str) -> tuple[float, str, float, float, list[str], float]:
        """Score one piece of text with both layers. Returns (score, label, rule_score, ml_score, reasons, ml_top)."""
        # Layer A: the strongest matching rule decides the rule score.
        rule_score, rule_label, reasons = 0.0, "benign", []
        if self.use_rules:
            for rule, snippet in rules.scan(text):
                reasons.append(f"rule:{rule.name} -> '{snippet}'")
                if rule.weight > rule_score:
                    rule_score, rule_label = rule.weight, rule.label

        # Layer B: the ML score is 1 minus the probability that the text is benign.
        ml_score, ml_label, ml_top = 0.0, "benign", 0.0
        if self.ml is not None:
            probs = self.ml.predict_proba(text)
            ml_score = 1.0 - probs.get("benign", 0.0)
            attack = {k: v for k, v in probs.items() if k != "benign"}
            ml_label = max(attack, key=attack.get)  # the most likely attack type
            ml_top = attack[ml_label]
            if ml_score >= self.flag_threshold:
                reasons.append(f"ml:{ml_label} p={ml_top:.2f} (non-benign {ml_score:.2f})")

        # The final score is whichever layer is more worried.
        if rule_score >= ml_score:
            return rule_score, rule_label, rule_score, ml_score, reasons, ml_top
        return ml_score, ml_label, rule_score, ml_score, reasons, ml_top

    def check(self, text: str, source: str = "user_input") -> Decision:
        """Classify a text and return the Decision (also recorded in self.events and the log file)."""
        # Score every window/sentence and keep the worst one.
        best = None
        for w in _segments(text):
            r = self._score_window(w)
            if best is None or r[0] > best[0]:
                best = r
        score, label, rule_score, ml_score, reasons, ml_top = best

        # Turn the score into an action using the two thresholds.
        if score >= self.block_threshold:
            action = "block"
        elif score >= self.flag_threshold:
            action = "flag"
        else:
            action, label = "allow", "benign"

        # Record the decision (the in-memory trail keeps only the latest 200).
        decision = Decision(action, label, round(score, 3), source, reasons,
                            round(rule_score, 3), round(ml_score, 3), round(ml_top, 3))
        self.events.append((text, decision))
        del self.events[:-200]
        if self.log:
            self._log(text, decision)
        return decision

    @staticmethod
    def _log(text: str, d: Decision) -> None:
        """Append one decision to the JSON-lines log file."""
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "text": text[:300], **asdict(d)}
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
