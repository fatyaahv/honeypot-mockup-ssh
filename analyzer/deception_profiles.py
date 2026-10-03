"""Finite, fictional Cowrie environment profiles and safe selection logic."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from types import MappingProxyType
from typing import Any


@dataclass(frozen=True)
class DeceptionProfile:
    name: str
    hostname: str
    users: tuple[str, ...]
    directories: tuple[str, ...]
    files: tuple[str, ...]
    artifacts: tuple[tuple[str, str], ...]
    system_info: tuple[tuple[str, str], ...]


_PROFILE_CATALOG: dict[str, DeceptionProfile] = {
    "generic_linux": DeceptionProfile(
        name="generic_linux",
        hostname="filesrv-02",
        users=("root", "backup", "operator"),
        directories=("/etc", "/home/backup", "/opt", "/var/log"),
        files=("/etc/hostname", "/etc/passwd", "/etc/os-release", "/var/log/auth.log"),
        artifacts=(("/etc/hostname", "filesrv-02"),
                    ("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nbackup:x:1001:1001:Backup User:/home/backup:/bin/bash\noperator:x:1002:1002:Operator:/home/operator:/bin/bash"),
                    ("/etc/os-release", "NAME=Ubuntu\nVERSION=22.04 LTS")),
        system_info=(("distribution", "Ubuntu 22.04 LTS"), ("kernel", "5.15.0-91-generic")),
    ),
    "web_server": DeceptionProfile(
        name="web_server",
        hostname="web-01",
        users=("root", "www-data", "deploy"),
        directories=("/var/www/html", "/etc/nginx", "/var/log/nginx", "/srv/app"),
        files=("/etc/passwd", "/etc/nginx/nginx.conf", "/var/www/html/index.html", "/srv/app/settings.ini"),
        artifacts=(("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:Web Service:/var/www:/usr/sbin/nologin\ndeploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash"),
                    ("/var/www/html/index.html", "Example Service\nStatus: operational"),
                    ("/srv/app/settings.ini", "environment=staging\nservice=portal")),
        system_info=(("distribution", "Ubuntu 22.04 LTS"), ("service", "nginx 1.18 (simulated)")),
    ),
    "database_server": DeceptionProfile(
        name="database_server",
        hostname="db-01",
        users=("root", "postgres", "dbadmin"),
        directories=("/var/lib/postgresql", "/etc/postgresql", "/var/log/postgresql", "/backup"),
        files=("/etc/passwd", "/etc/postgresql/14/main/postgresql.conf", "/var/log/postgresql/postgresql.log"),
        artifacts=(("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\npostgres:x:110:116:PostgreSQL Admin:/var/lib/postgresql:/bin/bash\ndbadmin:x:1001:1001:Database Admin:/home/dbadmin:/bin/bash"),
                    ("/etc/postgresql/14/main/postgresql.conf", "# simulated PostgreSQL configuration\nport = 5432"),
                    ("/var/log/postgresql/postgresql.log", "database system is ready to accept connections")),
        system_info=(("distribution", "Debian 12 (simulated)"), ("service", "PostgreSQL 14 (simulated)")),
    ),
    "developer_workstation": DeceptionProfile(
        name="developer_workstation",
        hostname="dev-ws-07",
        users=("root", "dev", "build"),
        directories=("/home/dev/projects", "/home/dev/.config", "/opt/toolchains", "/tmp/builds"),
        files=("/etc/passwd", "/home/dev/projects/README.txt", "/home/dev/projects/Makefile", "/home/dev/.config/editor.conf"),
        artifacts=(("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndev:x:1000:1000:Developer:/home/dev:/bin/bash\nbuild:x:1001:1001:Build User:/home/build:/bin/bash"),
                    ("/home/dev/projects/README.txt", "Internal sample project (simulated)"),
                    ("/home/dev/projects/Makefile", "# simulated build metadata\nall:; @echo build complete")),
        system_info=(("distribution", "Fedora 39 (simulated)"), ("tools", "git, gcc, python3 (simulated)")),
    ),
}
PROFILES = MappingProxyType(_PROFILE_CATALOG)

GENERIC_PROFILE = "generic_linux"
ALLOWED_PROFILE_NAMES = tuple(PROFILES)

_DATABASE_HINTS = (
    "postgres", "psql", "mysql", "mysqld", "mariadb", "redis-cli", "mongosh",
    "mongodb", "/var/lib/mysql", "/var/lib/postgresql", "5432", "3306",
)
_WEB_HINTS = (
    "nginx", "apache", "httpd", "/var/www", "wordpress", "php-fpm", "gunicorn",
    "uwsgi", "web server", "web application", "http service",
)
_DEVELOPER_HINTS = (
    "git ", "git status", "gcc", "make ", "npm", "node", "pip ", "pip3 ",
    "virtualenv", "venv", "developer", "source code", "build tool", "compiler",
)


def get_profile(name: str) -> DeceptionProfile:
    """Return a known, immutable profile; reject arbitrary profile names."""
    try:
        return PROFILES[name]
    except (KeyError, TypeError) as exc:
        raise ValueError("Unsupported deception profile.") from exc


def profile_as_dict(name: str) -> dict[str, Any]:
    """Return a JSON-serializable copy of a profile's safe simulated values."""
    profile = get_profile(name)
    data = asdict(profile)
    data["artifacts"] = {path: text for path, text in profile.artifacts}
    data["system_info"] = dict(profile.system_info)
    return data


def select_profile(
    context: dict[str, Any], analysis: dict[str, Any] | None = None
) -> dict[str, str]:
    """Choose a whitelisted profile from observable session clues and AI suggestion.

    Deterministic command/detection evidence wins. AI can refine only when no specific
    deterministic profile is indicated, and its suggestion must exactly match an allowlist.
    """
    clues = [str(item.get("command", "")) for item in context.get("commands", [])]
    clues.extend(str(item.get("alert_type", "")) for item in context.get("existing_detections", []))
    clues.extend(str(item.get("mapped_behavior", "")) for item in context.get("existing_detections", []))
    clues.extend(str(item) for item in context.get("mitre_technique_ids", []))
    if analysis:
        clues.extend(str(item.get("pattern", "")) for item in analysis.get("observed_patterns", []))
        clues.extend((str(analysis.get("likely_objective", "")), str(analysis.get("behavior_summary", ""))))
    text = "\n".join(clues).lower()

    if any(hint in text for hint in _DATABASE_HINTS):
        return {"profile": "database_server", "reason": "database service or data-store behavior was observed"}
    if any(hint in text for hint in _WEB_HINTS):
        return {"profile": "web_server", "reason": "web service or application behavior was observed"}
    if any(hint in text for hint in _DEVELOPER_HINTS):
        return {"profile": "developer_workstation", "reason": "developer or build tooling behavior was observed"}

    recommendation = analysis.get("recommended_profile") if analysis else None
    if recommendation in PROFILES:
        return {"profile": recommendation, "reason": "AI recommendation matched the fixed allowlist; no specific deterministic profile clue was found"}
    if recommendation is not None:
        return {"profile": GENERIC_PROFILE, "reason": "unsupported AI profile recommendation rejected; using generic fallback"}
    return {"profile": GENERIC_PROFILE, "reason": "no specific server or developer behavior was observed"}
