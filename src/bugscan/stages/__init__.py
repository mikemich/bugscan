"""All checks, in the order they run. Project-defined checks (from .bugscan/config.toml) run last."""
from .custom import Custom
from .deps import Deps
from .fuzz import Fuzz
from .lint import Lint
from .sanitize import Sanitize
from .sast import Sast
from .secrets import Secrets
from .tests import Tests
from .types import Types

BUILTIN = [Secrets, Sast, Lint, Deps, Types, Tests, Fuzz, Sanitize]


def all_stages(config):
    """Fresh instances per project, so nothing leaks between projects."""
    return [cls() for cls in BUILTIN] + [Custom(c) for c in config["checks"]]
