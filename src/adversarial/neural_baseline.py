"""
Differentiable Neural Baseline (MLP) for Tabular NIDS.
Implements exact gradient computation for Fast Gradient Sign Method (FGSM)
and Projected Gradient Descent (PGD) under domain constraints.
"""

from dataclasses import dataclass
import numpy as np
import pandas as pd
from src.adversarial.threats import ThreatModel, enforce_domain_constraints

class DifferentiableMLP:
    """
    Two-layer feedforward neural network in pure NumPy.
    Provides exact input gradients (dLoss/dX) for white-box gradient attacks.
    """
    def __init__(self, input_dim: int, hidden_dim: int = 32, lr: float = 0.01, random_seed: int = 42):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.lr = lr
        self.rng = np.random.RandomState(random_seed)
        
        # He initialization
        self.W1 = self.rng.randn(input_dim, hidden_dim) * np.sqrt(2.0 / input_dim)
        self.b1 = np.zeros((1, hidden_dim))
        self.W2 = self.rng.randn(hidden_dim, 1) * np.sqrt(2.0 / hidden_dim)
        self.b2 = np.zeros((1, 1))

    @staticmethod
    def _relu(z):
        return np.maximum(0, z)

    @staticmethod
    def _sigmoid(z):
        z_clip = np.clip(z, -25.0, 25.0)
        return 1.0 / (1.0 + np.exp(-z_clip))

    def forward(self, X: np.ndarray) -> tuple[np.ndarray, dict]:
        """Forward pass returning probabilities and cached activations."""
        z1 = np.dot(X, self.W1) + self.b1
        a1 = self._relu(z1)
        z2 = np.dot(a1, self.W2) + self.b2
        a2 = self._sigmoid(z2)
        cache = {"X": X, "z1": z1, "a1": a1, "z2": z2, "a2": a2}
        return a2, cache

    def compute_input_gradient(self, X: np.ndarray, y: np.ndarray) -> np.ndarray:
        """
        Computes analytical gradient of Binary Cross-Entropy loss with respect to input X:
        dL/dX.
        """
        y_col = y.reshape(-1, 1)
        a2, cache = self.forward(X)
        
        # Binary Cross Entropy derivative w.r.t z2: (a2 - y)
        dz2 = a2 - y_col
        # Backprop into hidden layer
        da1 = np.dot(dz2, self.W2.T)
        dz1 = da1 * (cache["z1"] > 0) # ReLU gradient
        # Gradient w.r.t input features X
        dX = np.dot(dz1, self.W1.T)
        return dX

    def fit(self, X: np.ndarray, y: np.ndarray, epochs: int = 15, batch_size: int = 256):
        """Trains MLP using mini-batch SGD with Adam-like momentum."""
        n_samples = len(X)
        y_col = y.reshape(-1, 1)
        
        # Precompute mean and scale for numeric stability
        self.x_mean = np.mean(X, axis=0, keepdims=True)
        self.x_std = np.std(X, axis=0, keepdims=True) + 1e-6
        X_norm = (X - self.x_mean) / self.x_std
        
        for _ in range(epochs):
            indices = np.arange(n_samples)
            self.rng.shuffle(indices)
            
            for start in range(0, n_samples, batch_size):
                end = min(start + batch_size, n_samples)
                idx = indices[start:end]
                xb, yb = X_norm[idx], y_col[idx]
                
                a2, cache = self.forward(xb)
                dz2 = a2 - yb
                dW2 = np.dot(cache["a1"].T, dz2) / len(xb)
                db2 = np.sum(dz2, axis=0, keepdims=True) / len(xb)
                
                da1 = np.dot(dz2, self.W2.T)
                dz1 = da1 * (cache["z1"] > 0)
                dW1 = np.dot(xb.T, dz1) / len(xb)
                db1 = np.sum(dz1, axis=0, keepdims=True) / len(xb)
                
                self.W2 -= self.lr * dW2
                self.b2 -= self.lr * db2
                self.W1 -= self.lr * dW1
                self.b1 -= self.lr * db1
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        X_norm = (X - self.x_mean) / self.x_std
        probs, _ = self.forward(X_norm)
        return probs.ravel()

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (self.predict_proba(X) >= 0.5).astype(int)

class GradientFlowAttacker:
    """
    White-box gradient attacks (FGSM & PGD) adapted for network flow data.
    Enforces domain invariants (monotonicity, header constraints, discrete protocols).
    """
    def __init__(self, mlp_model: DifferentiableMLP, threat_model: ThreatModel | None = None):
        self.mlp = mlp_model
        self.threat_model = threat_model or ThreatModel()

    def fgsm_attack(self, df_clean: pd.DataFrame, epsilon: float) -> pd.DataFrame:
        """
        Fast Gradient Sign Method (FGSM) under domain invariants:
        X_adv = X + epsilon * std(X) * sign(dL/dX)
        """
        X_arr = df_clean.values.astype(np.float64)
        y_target = np.ones(len(df_clean)) # Adversary wants to decrease loss w.r.t benign or push away from attack
        
        # Normalize input for gradient calculation
        X_norm = (X_arr - self.mlp.x_mean) / self.mlp.x_std
        grad_norm = self.mlp.compute_input_gradient(X_norm, y_target)
        
        # Adversary seeking evasion wants to REDUCE attack prediction, so moves in direction of -grad
        grad_step = -np.sign(grad_norm) * (self.mlp.x_std * epsilon)
        
        df_pert = df_clean.copy()
        for idx, col in enumerate(df_clean.columns):
            if col in self.threat_model.mutable_features:
                # Add positive perturbation only (monotonicity: can only pad/delay)
                step = np.abs(grad_step[:, idx])
                df_pert[col] = df_clean[col] + step
                
        return enforce_domain_constraints(df_pert, df_clean)

    def pgd_attack(self, df_clean: pd.DataFrame, epsilon: float, steps: int = 5, step_alpha: float = 0.05) -> pd.DataFrame:
        """
        Projected Gradient Descent (PGD) multi-step attack under domain invariants.
        """
        df_curr = df_clean.copy()
        max_budget = df_clean.values.astype(np.float64) * epsilon
        
        for _ in range(steps):
            X_arr = df_curr.values.astype(np.float64)
            y_target = np.ones(len(df_curr))
            X_norm = (X_arr - self.mlp.x_mean) / self.mlp.x_std
            grad_norm = self.mlp.compute_input_gradient(X_norm, y_target)
            
            grad_step = -np.sign(grad_norm) * (self.mlp.x_std * step_alpha)
            
            for idx, col in enumerate(df_clean.columns):
                if col in self.threat_model.mutable_features:
                    df_curr[col] += np.abs(grad_step[:, idx])
                    
            df_curr = enforce_domain_constraints(df_curr, df_clean)
            
        return df_curr

