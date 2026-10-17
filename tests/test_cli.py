from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from pip_fund import cli
from pip_fund.discovery import FundingDiscovery
from pip_fund.models import Failure, FundingRecord, Package, Report

if TYPE_CHECKING:
    from pathlib import Path


def test_empty_project_is_not_an_environment_scan(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    target_environment: tuple[Path, Path],
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "1"\n', encoding="utf-8"
    )

    status = cli.main(
        ["--project", str(tmp_path), "--python", str(target_environment[1])]
    )

    assert status == 0
    assert "Scanned 0 dependencies from project demo." in capsys.readouterr().out


def test_conflicting_scope_arguments_are_rejected() -> None:
    with pytest.raises(SystemExit) as error:
        cli.main(["--project", ".", "requests"])

    assert error.value.code == 2


@pytest.mark.parametrize(
    "arguments",
    [
        ["--extra", "test"],
        ["requests", "--group", "test"],
        ["--open"],
        ["requests", "urllib3", "--open"],
    ],
)
def test_invalid_option_combinations_are_rejected(arguments: list[str]) -> None:
    with pytest.raises(SystemExit) as error:
        cli.main(arguments)

    assert error.value.code == 2


def test_strict_mode_returns_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    report = Report(
        scope="project demo",
        packages=(),
        records=(),
        failures=(Failure(None, "project", "incomplete"),),
    )
    monkeypatch.setattr(cli, "create_report", lambda _: report)

    status = cli.main(["--strict"])

    assert status == 1
    assert "incomplete" in capsys.readouterr().out


def test_open_launches_the_only_destination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = Report(
        scope="packages demo",
        packages=(Package("demo", "1", True, 0),),
        records=(
            FundingRecord(
                "demo",
                "Funding",
                "https://example.com/pay",
                "https://example.com/pay",
                "metadata",
            ),
        ),
    )
    opened: list[str] = []
    monkeypatch.setattr(cli, "create_report", lambda _: report)
    monkeypatch.setattr("pip_fund.cli.webbrowser.open", opened.append)

    assert cli.main(["demo", "--open"]) == 0
    assert opened == ["https://example.com/pay"]


def test_open_rejects_ambiguous_result(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        cli,
        "create_report",
        lambda _: Report(scope="packages demo", packages=(), records=()),
    )

    assert cli.main(["demo", "--open"]) == 1
    assert "found 0" in capsys.readouterr().err


def test_console_entry_point_exits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "main", lambda: 7)

    with pytest.raises(SystemExit) as error:
        cli.cli()

    assert error.value.code == 7


def test_public_facade_exports_core_api() -> None:
    from pip_fund import fund

    assert fund.FundingDiscovery is FundingDiscovery


def test_default_scans_environment_outside_project(
    tmp_path, target_environment, monkeypatch, capsys
):
    root, executable = target_environment
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("VIRTUAL_ENV", str(root))
    assert cli.main(["--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["scope"] == "installed environment"
    assert report["interpreter"] == str(executable)
    assert report["summary"]["packages_scanned"] == 3


def test_default_does_not_read_current_project(
    tmp_path, target_environment, monkeypatch, capsys
):
    (tmp_path / "pyproject.toml").write_text("not valid toml", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert cli.main(["--python", str(target_environment[1])]) == 0
    assert "installed environment" in capsys.readouterr().out


def test_named_package_uses_target_dependency_graph(target_environment, capsys):
    assert (
        cli.main(["Alpha", "--python", str(target_environment[1]), "--format", "json"])
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["packages_scanned"] == 2
    packages = [p for d in report["destinations"] for p in d["packages"]]
    assert {p["name"] for p in packages} == {"Alpha", "Bravo"}
    assert next(p for p in packages if p["name"] == "Bravo")["parents"] == ["Alpha"]


def test_project_requires_environment(tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="demo"\ndependencies=[]\n', encoding="utf-8"
    )
    with pytest.raises(SystemExit) as error:
        cli.main(["--project", str(tmp_path)])
    assert error.value.code == 2
    assert "--python" in capsys.readouterr().err


def test_strict_missing_package_reports_target(target_environment, capsys):
    assert (
        cli.main(["Missing", "--python", str(target_environment[1]), "--strict"]) == 1
    )
    output = capsys.readouterr().out
    assert str(target_environment[1]) in output
    assert "package is not installed" in output
