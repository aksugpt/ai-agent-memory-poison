"""Evaluate rules-only, ML-only and combined guards.

1. Stratified 75/25 split of TRAIN (ML trained on the 75% only).
2. CHALLENGE set: paraphrases never used for training.
Reports the attack-detection rate and the false-positive rate, counting a flag or a block as "detected"
and, separately, counting only blocks.
"""
from sklearn.model_selection import train_test_split

from guard import dataset, ml
from guard.classifier import Guard
from guard.ml import MLGuard


def evaluate(name, guard, texts, labels):
    """Run one guard over labelled texts, print its detection / false-positive rates, return its mistakes."""
    n_attack = sum(label != "benign" for label in labels)
    n_benign = len(labels) - n_attack
    caught = fp = label_ok = blk_caught = blk_fp = 0
    misses, false_pos = [], []
    for t, label in zip(texts, labels):
        d = guard.check(t)
        flagged = d.action != "allow"  # flag or block counts as detected
        if label == "benign":
            blk_fp += d.blocked
            if flagged:
                fp += 1
                false_pos.append((t, d))  # a harmless text that was wrongly flagged or blocked
        else:
            blk_caught += d.blocked
            if flagged:
                caught += 1
                label_ok += d.label == label  # also count whether the attack type was named correctly
            else:
                misses.append((t, label, d))  # an attack that slipped through
    print(f"  {name:<9} flag+block: detect {caught}/{n_attack} ({caught / n_attack:.0%}), FP {fp}/{n_benign} ({fp / n_benign:.0%})"
          f" | block-only: detect {blk_caught}/{n_attack} ({blk_caught / n_attack:.0%}), FP {blk_fp}/{n_benign} ({blk_fp / n_benign:.0%})"
          f" | label ok {label_ok}/{n_attack}")
    return misses, false_pos


def run(title, texts, labels, ml_model):
    """Evaluate the three guard variants (rules only, ML only, both) on one dataset."""
    print(f"\n{title}  (n={len(texts)})")
    guards = {
        "rules": Guard(ml=None, use_rules=True, log=False),
        "ml": Guard(ml=MLGuard(ml_model), use_rules=False, log=False),
        "combined": Guard(ml=MLGuard(ml_model), use_rules=True, log=False),
    }
    return {name: evaluate(name, g, texts, labels) for name, g in guards.items()}


if __name__ == "__main__":
    # Train on 75% of the data so the other 25% is a fair test.
    texts, labels = dataset.flatten(dataset.TRAIN)
    tr_x, te_x, tr_y, te_y = train_test_split(texts, labels, test_size=0.25, stratify=labels, random_state=42)
    model = ml.train(tr_x, tr_y)

    # Test on the held-out split, then on the separate paraphrase (challenge) set.
    run("HELD-OUT SPLIT", te_x, te_y, model)
    ch_x, ch_y = dataset.flatten(dataset.CHALLENGE)
    res = run("CHALLENGE (paraphrases)", ch_x, ch_y, model)

    # List the combined guard's mistakes on the challenge set.
    misses, false_pos = res["combined"]
    print("\nCombined guard on CHALLENGE - missed:")
    for t, label, d in misses:
        print(f"  [{label}] score={d.score} :: {t}")
    print("Combined guard on CHALLENGE - false positives:")
    for t, d in false_pos:
        print(f"  [{d.label}] score={d.score} :: {t}")
