#!/usr/bin/env python3
"""Enforce Skan's GitHub Actions supply-chain policy without dependencies."""

from __future__ import annotations

import re
import sys
from pathlib import Path


USES_PATTERN = re.compile(
    r"^(?P<indent>\s*)(?P<list_marker>-\s*)?uses:\s*(?P<reference>[^#\s]+)"
)
PINNED_ACTION_PATTERN = re.compile(r"^[^@\s]+@[0-9a-fA-F]{40}$")
BLOCK_CREDENTIALS_PATTERN = re.compile(
    r"^persist-credentials:\s*false\s*(?:#.*)?$"
)
FLOW_CREDENTIALS_PATTERN = re.compile(
    r"(?:^\{|,)\s*persist-credentials\s*:\s*false\s*(?=,|\})"
)


def checkout_disables_credentials(
    lines: list[str], uses_index: int, step_indent: int
) -> bool:
    with_indent = step_indent + 2
    for index in range(uses_index + 1, len(lines)):
        line = lines[index]
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indentation = len(line) - len(stripped)
        if indentation <= step_indent:
            break
        if indentation != with_indent or not stripped.startswith("with:"):
            continue

        inline_mapping = stripped.removeprefix("with:").strip()
        if inline_mapping and not inline_mapping.startswith("#"):
            return FLOW_CREDENTIALS_PATTERN.search(inline_mapping) is not None

        input_indent = with_indent + 2
        for input_line in lines[index + 1 :]:
            input_stripped = input_line.lstrip()
            if not input_stripped or input_stripped.startswith("#"):
                continue
            indentation = len(input_line) - len(input_stripped)
            if indentation <= with_indent:
                break
            if indentation == input_indent and BLOCK_CREDENTIALS_PATTERN.fullmatch(
                input_stripped
            ):
                return True
        return False
    return False


def validate_workflow(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    errors: list[str] = []

    for index, line in enumerate(lines):
        match = USES_PATTERN.match(line)
        if match is None:
            continue

        reference = match.group("reference").strip("'\"")
        if reference.startswith("./"):
            continue

        location = f"{path}:{index + 1}"
        if PINNED_ACTION_PATTERN.fullmatch(reference) is None:
            errors.append(
                f"{location}: action reference must use a 40-character commit SHA: "
                f"{reference}"
            )

        action_name = reference.partition("@")[0].lower()
        if action_name == "actions/checkout":
            step_indent = len(match.group("indent"))
            if match.group("list_marker") is None:
                step_indent = max(step_indent - 2, 0)
            if not checkout_disables_credentials(lines, index, step_indent):
                errors.append(
                    f"{location}: actions/checkout must set persist-credentials: false"
                )

    return errors


def main(arguments: list[str]) -> int:
    if not arguments:
        print("usage: validate_workflow_policy.py WORKFLOW...", file=sys.stderr)
        return 2

    errors: list[str] = []
    for argument in arguments:
        path = Path(argument)
        try:
            errors.extend(validate_workflow(path))
        except (OSError, UnicodeError) as error:
            errors.append(f"{path}: unable to read workflow: {error}")

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
