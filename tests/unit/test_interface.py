from rich.text import Text

from msfauto.interface.app import _build_context_markup


def test_context_panel_markup_is_valid_rich_markup() -> None:
    markup = _build_context_markup(
        workspace_name="default",
        profile="safe",
        targets=["127.0.0.1"],
        ports="discovered ports",
    )

    parsed = Text.from_markup(markup)

    assert "WORKSPACE" in parsed.plain
    assert "PROFILE" in parsed.plain
    assert "127.0.0.1" in parsed.plain
    assert "discovered ports" in parsed.plain
    assert parsed.plain.count("\n") == 2
