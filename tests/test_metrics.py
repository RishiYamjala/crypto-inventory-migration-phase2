import math

import pytest

from src.metrics import _binomial_standard_error, _probability


def test_probability_uses_success_count_and_shot_count():
    assert _probability({"101": 3, "010": 7}, "101", 10) == pytest.approx(0.3)


def test_probability_returns_zero_when_marked_state_is_absent():
    assert _probability({"010": 10}, "101", 10) == 0.0


@pytest.mark.parametrize("shots", [0, -1, 1.5, True])
def test_probability_rejects_invalid_shot_counts(shots):
    with pytest.raises(ValueError, match="positive integer"):
        _probability({"101": 1}, "101", shots)


@pytest.mark.parametrize("bitstring", ["", "10x", "1 0"])
def test_probability_rejects_invalid_bitstrings(bitstring):
    with pytest.raises(ValueError, match="binary digits"):
        _probability({}, bitstring, 10)


@pytest.mark.parametrize("count", [-1, 11])
def test_probability_rejects_counts_outside_shot_range(count):
    with pytest.raises(ValueError, match="between 0 and shots"):
        _probability({"101": count}, "101", 10)


def test_binomial_standard_error_matches_formula():
    probability = 0.25
    shots = 100
    assert _binomial_standard_error(probability, shots) == pytest.approx(
        math.sqrt(probability * (1 - probability) / shots)
    )


@pytest.mark.parametrize("probability", [-0.01, 1.01])
def test_standard_error_rejects_invalid_probabilities(probability):
    with pytest.raises(ValueError, match="between 0 and 1"):
        _binomial_standard_error(probability, 100)


@pytest.mark.parametrize("shots", [0, -5, 10.5, False])
def test_standard_error_rejects_invalid_shot_counts(shots):
    with pytest.raises(ValueError, match="positive integer"):
        _binomial_standard_error(0.5, shots)


def test_standard_error_is_zero_at_probability_boundaries():
    assert _binomial_standard_error(0.0, 2048) == 0.0
    assert _binomial_standard_error(1.0, 2048) == 0.0
