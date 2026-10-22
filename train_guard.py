"""Train the guard's ML layer on the full TRAIN set and save it to models/guard.joblib."""
from guard import dataset, ml

if __name__ == "__main__":
    # Flatten the labelled examples, fit the model, and write it to disk.
    texts, labels = dataset.flatten(dataset.TRAIN)
    model = ml.train(texts, labels)
    ml.save(model)
    print(f"Trained on {len(texts)} examples -> {ml.MODEL_PATH}")
