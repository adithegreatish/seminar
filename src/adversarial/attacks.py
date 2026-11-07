"""
Adversarial Attack Algorithms for Tabular NIDS.
Implements Domain-Constrained Flow-Feature Perturbation (DC-FFP / DCPA) and Query-Guided Greedy Search (QGGS, formerly SGGS).
"""

from pathlib import Path
import numpy as np
import pandas as pd
from src.adversarial.threats import ThreatModel, enforce_domain_constraints
from src.models.baseline_models import NIDSModelWrapper

class DomainConstrainedPerturbationAttack:
    """
    Simulates physical network evasion via uniform proportional flow manipulation
    (payload padding, dummy packet injection, transmission delays).
    """
    def __init__(self, threat_model: ThreatModel | None = None):
        self.threat_model = threat_model or ThreatModel()

    def generate(self, X: pd.DataFrame, epsilon: float) -> pd.DataFrame:
        """
        Perturbs mutable features by a factor of epsilon (e.g. 0.10 = +10% padding/delay),
        enforcing domain constraints.
        """
        X_adv = X.copy()
        for col in self.threat_model.mutable_features:
            if col in X_adv.columns:
                # Add fractional perturbation
                perturbation = X_adv[col] * epsilon
                # Ensure minimum increment of 1 for integer features like packets
                if "PKTS" in col:
                    perturbation = np.maximum(perturbation, np.where(epsilon > 0, 1.0, 0.0))
                X_adv[col] = X_adv[col] + perturbation
                
        # Enforce all domain invariants
        return enforce_domain_constraints(X_adv, X)

class QueryGuidedGreedySearch:
    """
    Black-box query-based adversarial evasion attack (Query-Guided Greedy Search / QGGS).
    Directly queries the target model's output probabilities to identify the mutable feature
    whose perturbation most rapidly decreases the attack probability.
    
    Budget Semantics:
    max_epsilon (default 0.50) operates as an accumulated greedy-step budget.
    With step_budget = 0.05, the attack evaluates up to (max_epsilon / step_budget) = 10 sequential
    greedy steps. Successive updates on the same feature compound geometrically (1 + alpha)^k
    rather than imposing a strict per-feature linear L_inf norm cap against the clean vector.
    """
    def __init__(
        self,
        model_wrapper: NIDSModelWrapper,
        threat_model: ThreatModel | None = None,
        max_search_iterations: int = 3,
        step_budget: float = 0.05
    ):
        self.model = model_wrapper
        self.threat_model = threat_model or ThreatModel()
        self.max_search_iterations = max_search_iterations
        self.step_budget = step_budget

    def attack_sample(self, x_clean: pd.Series, max_epsilon: float = 0.50) -> tuple[pd.Series, bool, dict, float]:
        """
        Attacks a single malicious sample to evade detection.
        Returns: (x_perturbed, is_evaded, query_stats, final_prob)
        """
        x_curr = x_clean.copy()
        df_curr = pd.DataFrame([x_curr])
        
        # Initial clean evaluation query
        prob_init = self._get_attack_prob(df_curr)
        if prob_init < 0.5:
            # Already predicted as benign
            return x_clean, True, {"initial_query": 1, "search_queries": 0, "total_queries": 1}, prob_init
            
        initial_query = 1
        search_queries = 0
        iteration = 0
        curr_budget = 0.0
        
        while iteration < self.max_search_iterations and curr_budget < max_epsilon:
            iteration += 1
            best_feat = None
            best_prob = prob_init
            best_candidate = None
            
            # Test step increment on each mutable feature (up to 5 candidates per iteration)
            for feat in self.threat_model.mutable_features:
                if feat not in x_curr.index:
                    continue
                cand = x_curr.copy()
                step = cand[feat] * self.step_budget
                if "PKTS" in feat:
                    step = max(step, 1.0)
                cand[feat] += step
                
                df_cand = enforce_domain_constraints(pd.DataFrame([cand]), pd.DataFrame([x_clean]))
                prob = self._get_attack_prob(df_cand)
                search_queries += 1
                
                if prob < best_prob:
                    best_prob = prob
                    best_feat = feat
                    best_candidate = df_cand.iloc[0]
                    
            if best_candidate is not None and best_prob < prob_init:
                x_curr = best_candidate
                prob_init = best_prob
                curr_budget += self.step_budget
                if best_prob < 0.5:
                    q_stats = {"initial_query": initial_query, "search_queries": search_queries, "total_queries": initial_query + search_queries}
                    return x_curr, True, q_stats, best_prob
            else:
                # No single-feature candidate reduced the attack probability.
                # Greedy search has reached a local optimum / plateau; terminate search early.
                break
                    
        q_stats = {"initial_query": initial_query, "search_queries": search_queries, "total_queries": initial_query + search_queries}
        return x_curr, (prob_init < 0.5), q_stats, prob_init

    def attack_dataset(self, X_attacks: pd.DataFrame, max_epsilon: float = 0.50) -> tuple[pd.DataFrame, list[dict]]:
        """
        Performs greedy search evasion across an attack dataset.
        """
        perturbed_rows = []
        attack_logs = []
        for idx in range(len(X_attacks)):
            x_row = X_attacks.iloc[idx]
            x_adv, evaded, q_stats, final_p = self.attack_sample(x_row, max_epsilon=max_epsilon)
            perturbed_rows.append(x_adv)
            attack_logs.append({
                "sample_idx": idx,
                "evaded": bool(evaded),
                "initial_query": q_stats["initial_query"],
                "search_queries": q_stats["search_queries"],
                "total_queries": q_stats["total_queries"],
                "final_prob": float(final_p)
            })
            
        X_adv_df = pd.DataFrame(perturbed_rows, columns=X_attacks.columns, index=X_attacks.index)
        return X_adv_df, attack_logs

    def _get_attack_prob(self, df: pd.DataFrame) -> float:
        probs = self.model.predict_proba(df)
        if probs is not None:
            if len(probs.shape) > 1 and probs.shape[1] > 1:
                return float(probs[0, 1])
            return float(probs[0])
        preds, _ = self.model.predict(df)
        return float(preds[0])

# Backward-compatible alias for historical references in pipeline scripts
SurrogateGuidedGreedySearch = QueryGuidedGreedySearch


