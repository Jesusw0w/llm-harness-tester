"""Canary derivation and the normalisation echo suppression depends on."""

from inject_probe.canary import derive, normalize
from inject_probe.constants import FRAGMENT_SEPARATOR


def test_derivation_is_deterministic() -> None:
    assert derive(7, "direct.example") == derive(7, "direct.example")


def test_seed_changes_the_canary() -> None:
    assert derive(1, "direct.example") != derive(2, "direct.example")


def test_probe_id_changes_the_canary() -> None:
    assert derive(1, "direct.a") != derive(1, "direct.b")


def test_fragments_reconstruct_the_value() -> None:
    canary = derive(0, "direct.example")
    assert "".join(canary.fragments) == canary.value


def test_rendered_form_never_contains_the_value() -> None:
    """The whole echo defence in one assertion."""
    canary = derive(0, "direct.example")
    assert canary.value not in normalize(canary.rendered)
    assert canary.value not in normalize(canary.instruction)


def test_fragment_separator_is_not_whitespace() -> None:
    """A whitespace separator would collapse under `normalize` into a false hit."""
    assert FRAGMENT_SEPARATOR.strip() == FRAGMENT_SEPARATOR
    assert FRAGMENT_SEPARATOR != ""


def test_normalize_strips_every_kind_of_whitespace() -> None:
    assert normalize("CNRY a1\tb2\nc3\r\nd4") == "CNRYa1b2c3d4"


def test_normalize_leaves_zero_width_characters_alone() -> None:
    """Widening `normalize` past whitespace would break the echo guarantee."""
    zero_width_space = "\u200b"
    text = f"CN{zero_width_space}RY"
    assert normalize(text) == text
