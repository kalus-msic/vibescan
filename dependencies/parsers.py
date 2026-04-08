import re
from dataclasses import dataclass


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str


def parse_requirements_txt(content: str) -> list[Dependency]:
    """Parse requirements.txt content into a list of dependencies."""
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-") or line.startswith("http"):
            continue

        # Remove extras like [redis]
        line = re.sub(r"\[.*?\]", "", line)

        # Split on first version operator
        match = re.split(r"(==|>=|<=|~=|!=|>|<)", line, maxsplit=1)
        if len(match) < 3:
            continue  # no version specified

        name = match[0].strip()
        version = match[2].strip()
        # Handle multiple constraints: numpy!=1.24.0,>=1.23.0 — take last version
        if "," in version:
            parts = version.split(",")
            last_part = parts[-1].strip()
            version = re.sub(r"^(>=|<=|~=|!=|==|>|<)", "", last_part).strip()
        if name and version:
            deps.append(Dependency(name=name, version=version, ecosystem="PyPI"))
    return deps
