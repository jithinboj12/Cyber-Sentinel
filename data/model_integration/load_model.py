"""
Lightweight model loader for CyberSentinel.

Behavior:
- Attempts to load a sklearn model saved as model.joblib in the model_integration folder.
- If not present, trains a tiny RandomForest on synthetic data (for demo) and saves it.
- Exposes Detector.predict_proba(features_dict) returning probability of 'malicious'.
Note: The demo model is intentionally simple. Replace with your trained model for production.
"""

import os
import time
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.joblib")


class Detector:
    def __init__(self):
        self.pipeline = None
        if os.path.exists(MODEL_PATH):
            self.pipeline = joblib.load(MODEL_PATH)
        else:
            self.pipeline = self._train_demo_model()
            joblib.dump(self.pipeline, MODEL_PATH)

    def _train_demo_model(self):
        # Create synthetic dataset
        rng = np.random.RandomState(42)
        n = 1000
        src_port = rng.randint(1, 65535, n)
        dst_port = rng.randint(1, 65535, n)
        length = rng.randint(40, 1500, n)
        protocol = rng.choice(["TCP", "UDP", "ICMP", "OTHER"], n)
        tcp_flags = rng.choice(["", "S", "A", "F", "P", "R"], n)
        time_of_day = rng.rand(n) * 86400

        # Create labels: artificially make high dst_port & tiny payload suspicious sometimes
        label = ((dst_port > 1024) & (length < 200) & (protocol == "TCP")).astype(int)
        # Add some noise
        label = np.where(rng.rand(n) < 0.02, 1 - label, label)

        import pandas as pd

        df = pd.DataFrame(
            {
                "src_port": src_port,
                "dst_port": dst_port,
                "length": length,
                "protocol": protocol,
                "tcp_flags": tcp_flags,
                "time_of_day": time_of_day,
            }
        )

        numeric_features = ["src_port", "dst_port", "length", "time_of_day"]
        categorical_features = ["protocol", "tcp_flags"]

        preprocessor = ColumnTransformer(
            [
                ("num", "passthrough", numeric_features),
                ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features),
            ]
        )

        clf = RandomForestClassifier(n_estimators=50, random_state=42)
        pipeline = Pipeline([("pre", preprocessor), ("clf", clf)])

        pipeline.fit(df[numeric_features + categorical_features], label)
        return pipeline

    def predict_proba(self, features: dict):
        """
        features: dict with keys matching feature_mapping.json
        returns probability of malicious (float between 0 and 1)
        """
        import pandas as pd

        numeric_features = ["src_port", "dst_port", "length", "time_of_day"]
        categorical_features = ["protocol", "tcp_flags"]
        df = pd.DataFrame([ {k: features.get(k) for k in numeric_features + categorical_features} ])
        probs = self.pipeline.predict_proba(df)[:, 1]
        return float(probs[0])


if __name__ == "__main__":
    d = Detector()
    sample = {
        "src_port": 52344,
        "dst_port": 4444,
        "length": 100,
        "protocol": "TCP",
        "tcp_flags": "S",
        "time_of_day": 3600.0,
    }
    print("Demo probability (malicious):", d.predict_proba(sample))
