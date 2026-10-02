# SPDX-License-Identifier: Apache-2.0
"""TOML profile loading for Sandlock.

Profiles are parsed by the sandlock core, the parser the CLI uses, so one
profile cannot mean different things to the CLI and to the SDK. The core
returns the policy keyed by ``Sandbox`` field names, with ``${HOME}``
expanded and ``mount`` entries split into ``fs_mount`` and ``fs_mount_ro``.
``[program].exec`` and ``args`` are runtime program identity and are not
returned: pass them to ``sandbox.run(cmd)`` instead.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .exceptions import PolicyError
from .sandbox import BranchAction, Sandbox


def profiles_dir() -> Path:
    """Return ``~/.config/sandlock/profiles``, the profiles directory path."""
    from ._sdk import profile_dir

    try:
        return Path(profile_dir())
    except ValueError as e:
        raise PolicyError(str(e)) from None


def list_profiles() -> list[str]:
    """Return sorted names of available profiles."""
    directory = profiles_dir()
    if not directory.is_dir():
        return []
    return sorted(p.stem for p in directory.glob("*.toml") if p.is_file())


def load_profile(name: str) -> Sandbox:
    """Load a named profile and return a Sandbox.

    Raises:
        PolicyError: If the profile doesn't exist or has invalid fields.
    """
    path = profiles_dir() / f"{name}.toml"
    if not path.is_file():
        raise PolicyError(f"profile not found: {path}")
    return load_profile_path(path)


def load_profile_path(path: Path) -> Sandbox:
    """Load a profile from a file path and return a Sandbox.

    Raises:
        PolicyError: If the file can't be read or parsed, or has invalid fields.
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise PolicyError(f"{path}: {e}") from e
    return policy_from_toml(text, source=str(path))


def policy_from_toml(text: str, source: str = "<string>") -> Sandbox:
    """Construct a Sandbox from sectioned-schema TOML text.

    Raises:
        PolicyError: If the core parser rejects the profile.
    """
    from ._sdk import resolve_profile

    try:
        fields = resolve_profile(text)
    except ValueError as e:
        raise PolicyError(f"{source}: {e}") from None
    for key in ("on_exit", "on_error"):
        if key in fields:
            fields[key] = BranchAction(fields[key])
    return Sandbox(**fields)


def merge_cli_overrides(policy: Sandbox, overrides: dict) -> Sandbox:
    """Return a new Sandbox with CLI overrides applied on top of a profile.

    List fields from the CLI are appended to profile values.
    Scalar fields from the CLI replace profile values.
    """
    import dataclasses

    merged: dict[str, Any] = {}
    for key, value in overrides.items():
        current = getattr(policy, key, None)
        if isinstance(current, (list, tuple)) and isinstance(value, list):
            merged[key] = list(current) + value
        else:
            merged[key] = value

    return dataclasses.replace(policy, **merged)
