"""Layer B of the guard: a small machine-learning classifier (TF-IDF features + logistic regression)."""
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline, make_union

import config

# Where the trained model is saved and loaded from.
MODEL_PATH = config.ROOT / "models" / "guard.joblib"


def build_model():
    """Create an untrained model: text -> TF-IDF numbers -> logistic regression over the four labels."""
    # Two views of the text, joined together: word pairs (catch phrases) and 3-5 letter groups (survive typos).
    features = make_union(
        TfidfVectorizer(analyzer="word", ngram_range=(1, 2), sublinear_tf=True),
        TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True),
    )
    # class_weight="balanced" stops the larger classes from drowning out the smaller ones.
    clf = LogisticRegression(C=10, max_iter=2000, class_weight="balanced")
    return make_pipeline(features, clf)


def train(texts: list[str], labels: list[str]):
    """Train a new model on labelled example texts and return it."""
    model = build_model()
    model.fit(texts, labels)
    return model


def save(model, path: Path = MODEL_PATH) -> None:
    """Write a trained model to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)


class MLGuard:
    """Wraps a trained model so the guard can ask it for a probability per label."""

    def __init__(self, model):
        self.model = model

    @classmethod
    def load(cls, path: Path = MODEL_PATH) -> "MLGuard | None":
        """Load the saved model, or return None if it has not been trained yet."""
        return cls(joblib.load(path)) if path.exists() else None

    def predict_proba(self, text: str) -> dict[str, float]:
        """Return {label: probability} for one text (the probabilities add up to 1)."""
        probs = self.model.predict_proba([text])[0]
        return dict(zip(self.model.classes_, map(float, probs)))
