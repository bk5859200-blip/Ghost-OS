import os
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from src.core.path_manager import PathManager


class AnomalyDetector:
    """
    3-Stage Anomaly Detection Engine:
      - Stage A: Deterministic rule checks (spikes, threshold violations).
      - Stage B: Historical statistical baseline (rolling mean and std dev).
      - Stage C: Optional unsupervised Isolation Forest for multi-metric deviations.
    """

    def __init__(self, model_dir=None, model_name="anomaly_forest.pkl"):
        self.model_dir = model_dir or PathManager.get_models_dir()
        self.model_path = os.path.join(self.model_dir, model_name)
        self.scaler_path = os.path.join(self.model_dir, "scaler.pkl")
        self.model = None
        self.scaler = None
        self._history = []  # rolling window of telemetry vectors
        self.max_history = 300  # last 300 data points (~10 mins at 2s interval)
        os.makedirs(self.model_dir, exist_ok=True)
        self.load_model()

    def load_model(self):
        """Loads pre-trained model and scaler if available."""
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            try:
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                with open(self.scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
            except Exception:
                self.model = None
                self.scaler = None

    def add_telemetry_sample(self, metrics_dict):
        """Adds a live telemetry sample to rolling memory for baseline calculation."""
        vector = [
            metrics_dict.get("cpu_percent", 0.0),
            metrics_dict.get("ram_percent", 0.0),
            metrics_dict.get("disk_used_percent", 0.0),
            metrics_dict.get("disk_read_rate_mb", 0.0),
            metrics_dict.get("disk_write_rate_mb", 0.0),
            metrics_dict.get("net_sent_rate_mb", 0.0),
            metrics_dict.get("net_recv_rate_mb", 0.0),
        ]
        self._history.append(vector)
        if len(self._history) > self.max_history:
            self._history.pop(0)

    # ------------------------------------------------ Stage A: Deterministic
    def evaluate_rules(self, metrics_dict, thresholds):
        """
        Stage A: Checks hard operational thresholds.
        """
        anomalies = []
        cpu_crit = thresholds.get("cpu", {}).get("critical_percent", 90.0)
        mem_crit = thresholds.get("memory", {}).get("critical_percent", 95.0)

        cpu = metrics_dict.get("cpu_percent", 0.0)
        ram = metrics_dict.get("ram_percent", 0.0)

        if cpu >= cpu_crit:
            anomalies.append({
                "type": "cpu_critical",
                "score": min(100.0, (cpu / 100.0) * 90.0),
                "description": f"Sustained CPU usage at {cpu:.1f}% exceeds critical limit ({cpu_crit}%)"
            })

        if ram >= mem_crit:
            anomalies.append({
                "type": "ram_critical",
                "score": min(100.0, (ram / 100.0) * 90.0),
                "description": f"Physical RAM utilization at {ram:.1f}% exceeds critical limit ({mem_crit}%)"
            })

        return anomalies

    # ------------------------------------------------ Stage B: Baseline
    def evaluate_baseline(self, metrics_dict, z_threshold=3.0):
        """
        Stage B: Compares metrics against recent historical baseline using Z-score.
        """
        if len(self._history) < 30:
            return None  # insufficient baseline history

        history_arr = np.array(self._history)
        means = np.mean(history_arr, axis=0)
        stds = np.std(history_arr, axis=0)
        stds = np.where(stds == 0, 1.0, stds)  # avoid division by zero

        current_vector = np.array([
            metrics_dict.get("cpu_percent", 0.0),
            metrics_dict.get("ram_percent", 0.0),
            metrics_dict.get("disk_used_percent", 0.0),
            metrics_dict.get("disk_read_rate_mb", 0.0),
            metrics_dict.get("disk_write_rate_mb", 0.0),
            metrics_dict.get("net_sent_rate_mb", 0.0),
            metrics_dict.get("net_recv_rate_mb", 0.0),
        ])

        z_scores = np.abs((current_vector - means) / stds)
        max_z = float(np.max(z_scores))

        if max_z >= z_threshold:
            feature_names = ["CPU", "RAM", "Disk %", "Disk Read", "Disk Write", "Net Sent", "Net Recv"]
            max_feature_idx = int(np.argmax(z_scores))
            return {
                "is_anomaly": True,
                "z_score": round(max_z, 2),
                "feature": feature_names[max_feature_idx],
                "description": f"Metric '{feature_names[max_feature_idx]}' deviated {max_z:.1f}σ from recent baseline"
            }

        return None

    # ------------------------------------------------ Stage C: Isolation Forest
    def train(self, dataframe):
        """Trains Isolation Forest on historical telemetry DataFrame."""
        features = [
            'cpu_percent', 'ram_percent', 'disk_used_percent',
            'disk_read_rate', 'disk_write_rate', 'net_sent_rate', 'net_recv_rate'
        ]
        available = [c for c in features if c in dataframe.columns]
        if len(available) < len(features):
            raise ValueError(f"Missing telemetry columns for training: {set(features) - set(available)}")

        data = dataframe[features].values
        self.scaler = StandardScaler()
        scaled_data = self.scaler.fit_transform(data)

        self.model = IsolationForest(n_estimators=100, contamination=0.02, random_state=42)
        self.model.fit(scaled_data)

        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
        with open(self.scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)

    def predict_anomaly(self, current_vector):
        """Predicts multi-dimensional anomaly using pre-trained Isolation Forest."""
        if not self.model or not self.scaler:
            return False, 0.0

        try:
            arr = np.array(current_vector).reshape(1, -1)
            scaled = self.scaler.transform(arr)
            prediction = self.model.predict(scaled)[0]
            score = self.model.decision_function(scaled)[0]
            is_anomaly = bool(prediction == -1)
            return is_anomaly, float(score)
        except Exception:
            return False, 0.0
