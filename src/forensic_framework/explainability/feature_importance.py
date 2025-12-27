"""
Feature importance analysis for model interpretability.

Provides multiple methods for understanding which features
drive anomaly detection decisions:
1. Model-based importance (for tree models)
2. Permutation importance
3. Statistical correlation analysis
"""

from dataclasses import dataclass
from typing import Any, Literal

import numpy as np
from sklearn.base import BaseEstimator
from sklearn.inspection import permutation_importance


@dataclass
class FeatureImportance:
    """Importance of a single feature."""

    name: str
    importance: float
    rank: int
    method: str
    std: float | None = None  # Standard deviation for permutation importance

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "importance": self.importance,
            "rank": self.rank,
            "method": self.method,
            "std": self.std,
        }


class FeatureImportanceAnalyzer:
    """
    Analyze feature importance using multiple methods.

    Methods:
    - model: Use built-in feature_importances_ (tree models)
    - permutation: Permutation importance (model-agnostic)
    - correlation: Statistical correlation with target
    """

    def __init__(self, feature_names: list[str]):
        """
        Initialize analyzer.

        Args:
            feature_names: Names of features
        """
        self.feature_names = feature_names
        self._importances: dict[str, list[FeatureImportance]] = {}

    def analyze_model_importance(
        self,
        model: BaseEstimator,
    ) -> list[FeatureImportance]:
        """
        Extract importance from model's feature_importances_ attribute.

        Args:
            model: Fitted model with feature_importances_

        Returns:
            List of FeatureImportance sorted by importance
        """
        if not hasattr(model, "feature_importances_"):
            raise ValueError("Model does not have feature_importances_ attribute")

        importances = model.feature_importances_
        results = []

        for i, (name, imp) in enumerate(zip(self.feature_names, importances)):
            results.append(FeatureImportance(
                name=name,
                importance=float(imp),
                rank=0,  # Will be set after sorting
                method="model",
            ))

        # Sort and assign ranks
        results.sort(key=lambda x: x.importance, reverse=True)
        for rank, fi in enumerate(results, 1):
            fi.rank = rank

        self._importances["model"] = results
        return results

    def analyze_permutation_importance(
        self,
        model: BaseEstimator,
        X: np.ndarray,
        y: np.ndarray,
        n_repeats: int = 10,
        random_state: int = 42,
    ) -> list[FeatureImportance]:
        """
        Calculate permutation importance (model-agnostic).

        Args:
            model: Fitted model
            X: Feature matrix
            y: Target vector
            n_repeats: Number of permutation repeats
            random_state: Random seed

        Returns:
            List of FeatureImportance sorted by importance
        """
        result = permutation_importance(
            model, X, y,
            n_repeats=n_repeats,
            random_state=random_state,
        )

        results = []
        for i, name in enumerate(self.feature_names):
            results.append(FeatureImportance(
                name=name,
                importance=float(result.importances_mean[i]),
                rank=0,
                method="permutation",
                std=float(result.importances_std[i]),
            ))

        # Sort and assign ranks
        results.sort(key=lambda x: x.importance, reverse=True)
        for rank, fi in enumerate(results, 1):
            fi.rank = rank

        self._importances["permutation"] = results
        return results

    def analyze_correlation(
        self,
        X: np.ndarray,
        y: np.ndarray,
    ) -> list[FeatureImportance]:
        """
        Calculate correlation between features and target.

        Args:
            X: Feature matrix
            y: Target vector

        Returns:
            List of FeatureImportance sorted by absolute correlation
        """
        results = []

        for i, name in enumerate(self.feature_names):
            correlation = np.corrcoef(X[:, i], y)[0, 1]
            results.append(FeatureImportance(
                name=name,
                importance=abs(float(correlation)),
                rank=0,
                method="correlation",
            ))

        # Sort and assign ranks
        results.sort(key=lambda x: x.importance, reverse=True)
        for rank, fi in enumerate(results, 1):
            fi.rank = rank

        self._importances["correlation"] = results
        return results

    def get_consensus_ranking(self) -> list[FeatureImportance]:
        """
        Get consensus ranking across all methods.

        Uses average rank across methods weighted equally.

        Returns:
            List of FeatureImportance with consensus ranking
        """
        if not self._importances:
            raise RuntimeError("No importance analyses performed yet")

        # Collect ranks for each feature across methods
        feature_ranks: dict[str, list[int]] = {
            name: [] for name in self.feature_names
        }

        for method, importances in self._importances.items():
            for fi in importances:
                feature_ranks[fi.name].append(fi.rank)

        # Calculate average rank
        results = []
        for name, ranks in feature_ranks.items():
            avg_rank = np.mean(ranks)
            results.append(FeatureImportance(
                name=name,
                importance=1.0 / avg_rank,  # Higher importance = lower rank
                rank=0,
                method="consensus",
            ))

        # Sort and assign final ranks
        results.sort(key=lambda x: x.importance, reverse=True)
        for rank, fi in enumerate(results, 1):
            fi.rank = rank

        return results

    def generate_report(self) -> dict[str, Any]:
        """
        Generate comprehensive importance report.

        Returns:
            Dictionary with all analysis results
        """
        report = {
            "feature_count": len(self.feature_names),
            "methods_used": list(self._importances.keys()),
            "results": {},
        }

        for method, importances in self._importances.items():
            report["results"][method] = [fi.to_dict() for fi in importances]

        if len(self._importances) > 1:
            consensus = self.get_consensus_ranking()
            report["consensus"] = [fi.to_dict() for fi in consensus]

        return report


def main():
    """Demo feature importance analysis."""
    print("Feature Importance Analyzer Demo\n")

    from sklearn.datasets import make_classification
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.model_selection import train_test_split

    # Create synthetic data
    X, y = make_classification(
        n_samples=500,
        n_features=8,
        n_informative=5,
        n_redundant=2,
        random_state=42,
    )

    feature_names = [
        "hour_of_day",
        "time_since_last",
        "template_rarity",
        "severity_level",
        "message_length",
        "parameter_count",
        "ip_count",
        "path_count",
    ]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

    # Train model
    model = GradientBoostingClassifier(n_estimators=50, random_state=42)
    model.fit(X_train, y_train)

    # Analyze importance
    analyzer = FeatureImportanceAnalyzer(feature_names)

    print("Model-based importance:")
    model_imp = analyzer.analyze_model_importance(model)
    for fi in model_imp[:5]:
        print(f"  {fi.rank}. {fi.name}: {fi.importance:.4f}")

    print("\nPermutation importance:")
    perm_imp = analyzer.analyze_permutation_importance(model, X_test, y_test)
    for fi in perm_imp[:5]:
        print(f"  {fi.rank}. {fi.name}: {fi.importance:.4f} (±{fi.std:.4f})")

    print("\nCorrelation analysis:")
    corr_imp = analyzer.analyze_correlation(X_train, y_train)
    for fi in corr_imp[:5]:
        print(f"  {fi.rank}. {fi.name}: {fi.importance:.4f}")

    print("\nConsensus ranking:")
    consensus = analyzer.get_consensus_ranking()
    for fi in consensus[:5]:
        print(f"  {fi.rank}. {fi.name}")


if __name__ == "__main__":
    main()
