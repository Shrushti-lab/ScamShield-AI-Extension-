"""
ScamShield AI — Grey Wolf Optimizer (GWO) from Scratch
Bio-inspired metaheuristic optimizing hyperparameter search for URL scam classification.
Optimizes: n_estimators, max_depth, min_samples_split.
Fitness: Matthews Correlation Coefficient (MCC) via Stratified K-Fold CV.
Logs convergence history.
"""
from __future__ import annotations
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import matthews_corrcoef


class GreyWolfOptimizer:
    """
    Implementation of Grey Wolf Optimizer (Mirjalili et al., 2014)
    Tunes:
      param 0: n_estimators (int, lower..upper)
      param 1: max_depth (int, lower..upper)
      param 2: min_samples_split (int, lower..upper)
    """

    def __init__(
        self,
        num_wolves: int = 8,
        max_iter: int = 10,
        bounds: list[tuple[float, float]] = None,
        random_state: int = 42,
    ):
        self.num_wolves = num_wolves
        self.max_iter = max_iter
        # Bounds: [(n_estimators_min, max), (max_depth_min, max), (min_samples_split_min, max)]
        self.bounds = bounds or [(30, 160), (4, 20), (2, 8)]
        self.dim = len(self.bounds)
        self.rng = np.random.RandomState(random_state)
        self.convergence_curve: list[float] = []

        # Wolves: Alpha (best), Beta (2nd best), Delta (3rd best)
        self.alpha_pos = np.zeros(self.dim)
        self.alpha_score = -float("inf")

        self.beta_pos = np.zeros(self.dim)
        self.beta_score = -float("inf")

        self.delta_pos = np.zeros(self.dim)
        self.delta_score = -float("inf")

    def _clip_to_bounds(self, pos: np.ndarray) -> np.ndarray:
        clipped = np.copy(pos)
        for d in range(self.dim):
            low, high = self.bounds[d]
            clipped[d] = np.clip(clipped[d], low, high)
        return clipped

    def evaluate_fitness(self, pos: np.ndarray, X: np.ndarray, y: np.ndarray) -> float:
        """
        Fitness = MCC across Stratified 3-Fold Cross-Validation.
        """
        n_est = int(round(pos[0]))
        max_d = int(round(pos[1]))
        min_split = int(round(pos[2]))

        skf = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
        mcc_scores = []

        for train_idx, val_idx in skf.split(X, y):
            X_tr, X_val = X[train_idx], X[val_idx]
            y_tr, y_val = y[train_idx], y[val_idx]

            clf = RandomForestClassifier(
                n_estimators=n_est,
                max_depth=max_d,
                min_samples_split=min_split,
                random_state=42,
                n_jobs=-1,
            )
            clf.fit(X_tr, y_tr)
            y_pred = clf.predict(X_val)
            mcc = matthews_corrcoef(y_val, y_pred)
            mcc_scores.append(mcc)

        return float(np.mean(mcc_scores))

    def optimize(self, X: np.ndarray, y: np.ndarray) -> dict:
        """
        Executes GWO search loop on the given dataset.
        Returns: {
            best_params: dict,
            best_mcc: float,
            convergence_curve: list[float]
        }
        """
        # Initialize wolf pack randomly within bounds
        positions = np.zeros((self.num_wolves, self.dim))
        for i in range(self.num_wolves):
            for d in range(self.dim):
                low, high = self.bounds[d]
                positions[i, d] = self.rng.uniform(low, high)

        self.convergence_curve = []

        for it in range(self.max_iter):
            # Calculate a linearly decaying from 2 to 0
            a = 2.0 - it * (2.0 / self.max_iter)

            # Evaluate each wolf's fitness
            for i in range(self.num_wolves):
                positions[i] = self._clip_to_bounds(positions[i])
                fitness = self.evaluate_fitness(positions[i], X, y)

                # Update Alpha, Beta, Delta
                if fitness > self.alpha_score:
                    self.delta_score = self.beta_score
                    self.delta_pos = np.copy(self.beta_pos)

                    self.beta_score = self.alpha_score
                    self.beta_pos = np.copy(self.alpha_pos)

                    self.alpha_score = fitness
                    self.alpha_pos = np.copy(positions[i])

                elif fitness > self.beta_score:
                    self.delta_score = self.beta_score
                    self.delta_pos = np.copy(self.beta_pos)

                    self.beta_score = fitness
                    self.beta_pos = np.copy(positions[i])

                elif fitness > self.delta_score:
                    self.delta_score = fitness
                    self.delta_pos = np.copy(positions[i])

            self.convergence_curve.append(float(round(self.alpha_score, 4)))

            # Update wolf positions using Alpha, Beta, Delta guidance
            for i in range(self.num_wolves):
                for d in range(self.dim):
                    r1 = self.rng.uniform(0, 1)
                    r2 = self.rng.uniform(0, 1)
                    A1 = 2 * a * r1 - a
                    C1 = 2 * r2
                    D_alpha = abs(C1 * self.alpha_pos[d] - positions[i, d])
                    X1 = self.alpha_pos[d] - A1 * D_alpha

                    r1 = self.rng.uniform(0, 1)
                    r2 = self.rng.uniform(0, 1)
                    A2 = 2 * a * r1 - a
                    C2 = 2 * r2
                    D_beta = abs(C2 * self.beta_pos[d] - positions[i, d])
                    X2 = self.beta_pos[d] - A2 * D_beta

                    r1 = self.rng.uniform(0, 1)
                    r2 = self.rng.uniform(0, 1)
                    A3 = 2 * a * r1 - a
                    C3 = 2 * r2
                    D_delta = abs(C3 * self.delta_pos[d] - positions[i, d])
                    X3 = self.delta_pos[d] - A3 * D_delta

                    positions[i, d] = (X1 + X2 + X3) / 3.0

                positions[i] = self._clip_to_bounds(positions[i])

        best_params = {
            "n_estimators": int(round(self.alpha_pos[0])),
            "max_depth": int(round(self.alpha_pos[1])),
            "min_samples_split": int(round(self.alpha_pos[2])),
        }

        return {
            "best_params": best_params,
            "best_mcc": float(round(self.alpha_score, 4)),
            "convergence_curve": self.convergence_curve,
        }
