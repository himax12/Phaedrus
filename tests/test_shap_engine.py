"""
Tests for SHAP engine.
"""

import numpy as np
import pytest
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.datasets import make_classification
from sklearn.model_selection import train_test_split


class TestSHAPEngine:
    """Test SHAP explainability engine."""

    @pytest.fixture
    def trained_model_and_data(self):
        """Create trained model and data for testing."""
        X, y = make_classification(
            n_samples=200,
            n_features=8,
            n_informative=5,
            random_state=42,
        )
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

        model = GradientBoostingClassifier(n_estimators=20, random_state=42)
        model.fit(X_train, y_train)

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

        return model, X_train, X_test, feature_names

    def test_shap_engine_init(self):
        from forensic_framework.explainability import SHAPEngine

        engine = SHAPEngine()
        assert engine is not None

    def test_shap_fit_and_explain(self, trained_model_and_data):
        from forensic_framework.explainability import SHAPEngine

        model, X_train, X_test, feature_names = trained_model_and_data

        engine = SHAPEngine()
        engine.fit(model, X_train, feature_names)

        result = engine.explain(X_test[0], log_id="test-001", save_plot=False)

        assert result.log_id == "test-001"
        assert len(result.contributions) == len(feature_names)
        assert result.base_value is not None

    def test_shap_top_contributors(self, trained_model_and_data):
        from forensic_framework.explainability import SHAPEngine

        model, X_train, X_test, feature_names = trained_model_and_data

        engine = SHAPEngine()
        engine.fit(model, X_train, feature_names)

        result = engine.explain(X_test[0], log_id="test-002", save_plot=False)
        top = result.get_top_contributors(3)

        assert len(top) == 3
        # Top contributors should be sorted by absolute contribution
        assert abs(top[0].contribution) >= abs(top[1].contribution)

    def test_shap_narrative(self, trained_model_and_data):
        from forensic_framework.explainability import SHAPEngine

        model, X_train, X_test, feature_names = trained_model_and_data

        engine = SHAPEngine()
        engine.fit(model, X_train, feature_names)

        result = engine.explain(X_test[0], log_id="test-003", save_plot=False)
        narrative = result.get_narrative()

        assert isinstance(narrative, str)
        assert len(narrative) > 0
