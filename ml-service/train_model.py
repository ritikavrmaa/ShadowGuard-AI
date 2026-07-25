from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix


RANDOM_SEED = 42
MODEL_PATH = Path(__file__).parent / "shadowguard_iforest.joblib"


def generate_normal_data(samples: int = 2000) -> np.ndarray:
    rng = np.random.default_rng(RANDOM_SEED)
    rows = []

    for _ in range(samples):
        identity_type = int(rng.integers(0, 2))

        if identity_type == 0:
            requests = int(np.clip(rng.normal(5, 1.3), 1, 8))
            unique_files = int(np.clip(rng.normal(3, 1.1), 1, 7))
        else:
            requests = int(np.clip(rng.normal(2, 0.7), 1, 3))
            unique_files = int(np.clip(rng.normal(2, 0.8), 1, 4))

        failed_requests = int(rng.choice([0, 0, 0, 0, 1]))
        sensitive_accesses = int(rng.choice([0, 0, 0, 0, 1]))

        rows.append(
            [
                requests,
                unique_files,
                failed_requests,
                sensitive_accesses,
                identity_type,
            ]
        )

    return np.asarray(rows, dtype=float)


def generate_attack_data(samples: int = 250) -> np.ndarray:
    rng = np.random.default_rng(RANDOM_SEED + 1)
    rows = []

    for _ in range(samples):
        identity_type = int(rng.choice([0, 1], p=[0.2, 0.8]))
        requests = int(rng.integers(9, 21))
        unique_files = int(rng.integers(6, 16))
        failed_requests = int(rng.integers(2, 8))
        sensitive_accesses = int(rng.integers(1, 6))

        rows.append(
            [
                requests,
                unique_files,
                failed_requests,
                sensitive_accesses,
                identity_type,
            ]
        )

    return np.asarray(rows, dtype=float)


def main() -> None:
    normal_data = generate_normal_data()
    attack_data = generate_attack_data()

    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )

    model.fit(normal_data)

    normal_predictions = model.predict(normal_data)
    attack_predictions = model.predict(attack_data)

    expected = np.concatenate(
        [
            np.zeros(len(normal_data), dtype=int),
            np.ones(len(attack_data), dtype=int),
        ]
    )

    predicted = np.concatenate(
        [
            (normal_predictions == -1).astype(int),
            (attack_predictions == -1).astype(int),
        ]
    )

    print("\nConfusion matrix:")
    print(confusion_matrix(expected, predicted))

    print("\nValidation report:")
    print(
        classification_report(
            expected,
            predicted,
            target_names=["NORMAL", "ANOMALY"],
            zero_division=0,
        )
    )

    normal_accepted = int(np.sum(normal_predictions == 1))
    attacks_flagged = int(np.sum(attack_predictions == -1))

    print(
        f"\nNormal samples accepted: "
        f"{normal_accepted}/{len(normal_data)}"
    )

    print(
        f"Attack samples flagged: "
        f"{attacks_flagged}/{len(attack_data)}"
    )

    artifact = {
        "model": model,
        "feature_names": [
            "requests10s",
            "uniqueFiles",
            "failedRequests",
            "sensitiveFileAccesses",
            "identityType",
        ],
        "identity_encoding": {
            "HUMAN": 0,
            "MACHINE": 1,
        },
        "training_samples": len(normal_data),
    }

    joblib.dump(artifact, MODEL_PATH)

    print(f"\nModel saved to: {MODEL_PATH}")


if __name__ == "__main__":
    main()