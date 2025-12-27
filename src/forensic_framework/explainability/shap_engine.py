"""
SHAP-based explainability engine for forensic AI decisions.

Generates SHAP (SHapley Additive exPlanations) visualizations that
transform "black box" AI scores into interpretable feature contributions.

This is critical for:
- Forensic reporting (ISO 27037 compliance)
- Court-ready evidence explanation
- Investigator understanding of AI decisions
"""

import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for server use
import matplotlib.pyplot as plt
import numpy as np
import shap
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest


@dataclass
class FeatureContribution:
    """A single feature's contribution to the prediction."""

    name: str
    value: float  # Original feature value
    contribution: float  # SHAP value (positive = increases anomaly score)
    description: str | None = None


@dataclass
class SHAPResult:
    """Result of SHAP analysis for a single prediction."""

    log_id: str
    base_value: float  # Expected value (average prediction)
    final_value: float  # Actual prediction
    contributions: list[FeatureContribution]
    plot_path: Path | None = None
    plot_base64: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "log_id": self.log_id,
            "base_value": self.base_value,
            "final_value": self.final_value,
            "contributions": [
                {
                    "name": c.name,
                    "value": c.value,
                    "contribution": c.contribution,
                    "description": c.description,
                }
                for c in self.contributions
            ],
            "plot_path": str(self.plot_path) if self.plot_path else None,
        }

    def get_top_contributors(self, n: int = 5) -> list[FeatureContribution]:
        """Get top N contributing features by absolute contribution."""
        sorted_contribs = sorted(
            self.contributions,
            key=lambda c: abs(c.contribution),
            reverse=True,
        )
        return sorted_contribs[:n]

    def get_narrative(self) -> str:
        """Generate a human-readable narrative of the explanation."""
        top = self.get_top_contributors(3)

        if not top:
            return "No significant contributing factors identified."

        parts = []
        for contrib in top:
            direction = "increased" if contrib.contribution > 0 else "decreased"
            parts.append(
                f"{contrib.name} ({contrib.value:.2f}) {direction} "
                f"the score by {abs(contrib.contribution):.3f}"
            )

        return f"The anomaly score of {self.final_value:.2f} was primarily driven by: " + "; ".join(parts)


class SHAPEngine:
    """
    SHAP explainability engine for forensic AI models.

    Supports:
    - TreeExplainer for tree-based models (GradientBoosting, IsolationForest)
    - Waterfall plots for individual predictions
    - Summary plots for overview

    Usage:
        engine = SHAPEngine()
        engine.fit(model, X_train, feature_names)
        result = engine.explain(X_test[0], log_id="log-001")
    """

    # Feature descriptions for forensic context
    FEATURE_DESCRIPTIONS = {
        "hour_of_day": "Time of day (0-23 hours)",
        "day_of_week": "Day of week (0=Monday, 6=Sunday)",
        "time_since_last": "Seconds since previous event",
        "template_frequency": "How common this log type is",
        "template_rarity": "How rare this log type is",
        "source_frequency": "How common this source is",
        "severity_level": "Log severity (0=DEBUG, 4=CRITICAL)",
        "message_length": "Character count of log message",
        "parameter_count": "Number of extracted parameters",
        "ip_count": "Number of IP addresses involved",
        "path_count": "Number of file paths mentioned",
    }

    def __init__(
        self,
        output_dir: Path | None = None,
        plot_format: Literal["png", "svg"] = "png",
    ):
        """
        Initialize SHAP engine.

        Args:
            output_dir: Directory to save plots
            plot_format: Output format for plots
        """
        self.output_dir = output_dir
        self.plot_format = plot_format
        self.explainer: shap.Explainer | None = None
        self.feature_names: list[str] = []
        self._base_value: float = 0.0

        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)

    def fit(
        self,
        model: Any,
        X_train: np.ndarray,
        feature_names: list[str],
    ) -> None:
        """
        Fit the SHAP explainer on training data.

        Args:
            model: Trained model (tree-based recommended)
            X_train: Training data for background
            feature_names: Names of features
        """
        self.feature_names = feature_names

        # Use appropriate explainer based on model type
        if isinstance(model, (GradientBoostingClassifier,)):
            # TreeExplainer for tree-based models
            self.explainer = shap.TreeExplainer(model)
        elif isinstance(model, IsolationForest):
            # For IsolationForest, use KernelExplainer with sample background
            # Sample a subset for background to keep it manageable
            background = shap.sample(X_train, min(100, len(X_train)))
            self.explainer = shap.KernelExplainer(
                model.decision_function, background
            )
        else:
            # Fallback to KernelExplainer
            background = shap.sample(X_train, min(100, len(X_train)))
            predict_fn = getattr(model, "predict_proba", model.predict)
            self.explainer = shap.KernelExplainer(predict_fn, background)

    def explain(
        self,
        X: np.ndarray,
        log_id: str,
        save_plot: bool = True,
    ) -> SHAPResult:
        """
        Generate SHAP explanation for a single prediction.

        Args:
            X: Feature vector (1D array)
            log_id: Identifier for the log entry
            save_plot: Whether to save waterfall plot

        Returns:
            SHAPResult with contributions and plot
        """
        if self.explainer is None:
            raise RuntimeError("Explainer not fitted. Call fit() first.")

        # Ensure 2D input
        X_2d = X.reshape(1, -1) if X.ndim == 1 else X

        # Calculate SHAP values
        shap_values = self.explainer.shap_values(X_2d)

        # Handle different SHAP output formats
        if isinstance(shap_values, list):
            # Multi-class output - use last class (anomaly)
            shap_values = shap_values[-1]

        shap_values = shap_values.flatten()

        # Get base value
        base_value = (
            self.explainer.expected_value
            if isinstance(self.explainer.expected_value, float)
            else self.explainer.expected_value[-1]
        )
        self._base_value = float(base_value)

        # Calculate final value
        final_value = self._base_value + np.sum(shap_values)

        # Create feature contributions
        contributions = []
        for i, (name, value, shap_val) in enumerate(
            zip(self.feature_names, X_2d.flatten(), shap_values)
        ):
            contributions.append(FeatureContribution(
                name=name,
                value=float(value),
                contribution=float(shap_val),
                description=self.FEATURE_DESCRIPTIONS.get(name),
            ))

        result = SHAPResult(
            log_id=log_id,
            base_value=self._base_value,
            final_value=float(final_value),
            contributions=contributions,
        )

        # Generate and save plot
        if save_plot:
            plot_path, plot_base64 = self._generate_waterfall_plot(
                shap_values, X_2d.flatten(), log_id
            )
            result.plot_path = plot_path
            result.plot_base64 = plot_base64

        return result

    def _generate_waterfall_plot(
        self,
        shap_values: np.ndarray,
        feature_values: np.ndarray,
        log_id: str,
    ) -> tuple[Path | None, str | None]:
        """Generate waterfall plot for the explanation."""
        import base64

        plt.figure(figsize=(10, 6))

        # Create SHAP Explanation object for waterfall plot
        explanation = shap.Explanation(
            values=shap_values,
            base_values=self._base_value,
            data=feature_values,
            feature_names=self.feature_names,
        )

        # Generate waterfall plot
        shap.plots.waterfall(explanation, show=False)
        plt.title(f"SHAP Explanation for {log_id}")
        plt.tight_layout()

        # Save to file and/or base64
        plot_path = None
        plot_base64 = None

        if self.output_dir:
            plot_path = self.output_dir / f"shap_{log_id}.{self.plot_format}"
            plt.savefig(plot_path, dpi=150, bbox_inches="tight")

        # Also generate base64 for embedding in reports
        buffer = io.BytesIO()
        plt.savefig(buffer, format="png", dpi=150, bbox_inches="tight")
        buffer.seek(0)
        plot_base64 = base64.b64encode(buffer.read()).decode("utf-8")

        plt.close()

        return plot_path, plot_base64

    def generate_summary_plot(
        self,
        X: np.ndarray,
        log_ids: list[str] | None = None,
        filename: str = "shap_summary",
    ) -> Path | None:
        """
        Generate summary plot for multiple predictions.

        Args:
            X: Feature matrix (2D array)
            log_ids: Optional identifiers for logs
            filename: Base filename for the plot

        Returns:
            Path to saved plot
        """
        if self.explainer is None:
            raise RuntimeError("Explainer not fitted. Call fit() first.")

        shap_values = self.explainer.shap_values(X)

        if isinstance(shap_values, list):
            shap_values = shap_values[-1]

        plt.figure(figsize=(10, 8))
        shap.summary_plot(
            shap_values,
            X,
            feature_names=self.feature_names,
            show=False,
        )
        plt.tight_layout()

        plot_path = None
        if self.output_dir:
            plot_path = self.output_dir / f"{filename}.{self.plot_format}"
            plt.savefig(plot_path, dpi=150, bbox_inches="tight")

        plt.close()
        return plot_path


def main():
    """Demo SHAP engine functionality."""
    print("SHAP Engine Demo\n")

    from sklearn.datasets import make_classification
    from sklearn.model_selection import train_test_split

    # Create synthetic data
    print("Creating synthetic anomaly detection data...")
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

    # Train a model
    print("Training GradientBoosting classifier...")
    model = GradientBoostingClassifier(n_estimators=50, random_state=42)
    model.fit(X_train, y_train)

    # Initialize SHAP engine
    print("Fitting SHAP explainer...")
    engine = SHAPEngine()
    engine.fit(model, X_train, feature_names)

    # Explain a prediction
    print("\nExplaining prediction for test sample:")
    result = engine.explain(X_test[0], log_id="test-log-001", save_plot=False)

    print(f"\n  Log ID: {result.log_id}")
    print(f"  Base Value: {result.base_value:.3f}")
    print(f"  Final Value: {result.final_value:.3f}")
    print("\n  Top Contributing Features:")

    for contrib in result.get_top_contributors(5):
        direction = "↑" if contrib.contribution > 0 else "↓"
        print(
            f"    {direction} {contrib.name}: "
            f"value={contrib.value:.2f}, contribution={contrib.contribution:+.3f}"
        )

    print(f"\n  Narrative: {result.get_narrative()}")


if __name__ == "__main__":
    main()
