from pathlib import Path
from typing import Any

import joblib
import numpy as np
from flask import Flask, jsonify, request
from flask_cors import CORS


BASE_DIR = Path(__file__).parent
MODEL_PATH = BASE_DIR / "shadowguard_iforest.joblib"

app = Flask(__name__)
CORS(app)

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        "Model file not found. Run: python train_model.py"
    )

artifact = joblib.load(MODEL_PATH)
model = artifact["model"]

IDENTITY_ENCODING = artifact.get(
    "identity_encoding",
    {
        "HUMAN": 0,
        "MACHINE": 1,
    },
)


def read_non_negative_number(
    payload: dict[str, Any],
    key: str,
) -> float:
    value = float(payload.get(key, 0))

    if value < 0:
        raise ValueError(f"{key} cannot be negative")

    return value


@app.get("/")
def health():
    return jsonify(
        {
            "status": "online",
            "service": "ShadowGuard ML Anomaly Detector",
            "model": "Isolation Forest",
            "trainingSamples": artifact.get("training_samples", 0),
        }
    )


@app.post("/predict")
def predict():
    try:
        payload = request.get_json(silent=True)

        if not isinstance(payload, dict):
            return jsonify(
                {"error": "JSON request body is required"}
            ), 400

        identity_type = str(
            payload.get("identityType", "MACHINE")
        ).upper()

        if identity_type not in IDENTITY_ENCODING:
            return jsonify(
                {
                    "error": (
                        "identityType must be HUMAN or MACHINE"
                    )
                }
            ), 400

        requests_10s = read_non_negative_number(
            payload,
            "requests10s",
        )

        unique_files = read_non_negative_number(
            payload,
            "uniqueFiles",
        )

        failed_requests = read_non_negative_number(
            payload,
            "failedRequests",
        )

        sensitive_accesses = read_non_negative_number(
            payload,
            "sensitiveFileAccesses",
        )

        features = np.asarray(
            [
                [
                    requests_10s,
                    unique_files,
                    failed_requests,
                    sensitive_accesses,
                    IDENTITY_ENCODING[identity_type],
                ]
            ],
            dtype=float,
        )

        prediction = int(model.predict(features)[0])
        decision_score = float(
            model.decision_function(features)[0]
        )

        is_anomaly = prediction == -1

        anomaly_score = round(
            max(
                0.0,
                min(
                    100.0,
                    50.0 - decision_score * 200.0,
                ),
            ),
            2,
        )

        return jsonify(
            {
                "isAnomaly": is_anomaly,
                "prediction": (
                    "ANOMALY" if is_anomaly else "NORMAL"
                ),
                "anomalyScore": anomaly_score,
                "decisionScore": round(decision_score, 6),
                "model": "Isolation Forest",
                "features": {
                    "requests10s": requests_10s,
                    "uniqueFiles": unique_files,
                    "failedRequests": failed_requests,
                    "sensitiveFileAccesses": sensitive_accesses,
                    "identityType": identity_type,
                },
            }
        )

    except (TypeError, ValueError) as error:
        return jsonify({"error": str(error)}), 400

    except Exception as error:
        app.logger.exception("Prediction failed")

        return jsonify(
            {
                "error": "ML prediction failed",
                "details": str(error),
            }
        ), 500


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5001,
        debug=False,
    )