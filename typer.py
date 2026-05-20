"""Minimal Typer-compatible shim for local CLI tests.

This implements only the subset of Typer used by the ChainScope scripts:
- Typer()
- @app.command()
- Option(...)
- Argument(...)
- echo(...)
- Exit(code)
"""

from __future__ import annotations

import argparse
import inspect
import sys
from dataclasses import dataclass, field


class Exit(SystemExit):
    def __init__(self, code: int = 0):
        super().__init__(code)
        self.code = code


def echo(message="", err: bool = False):
    stream = sys.stderr if err else sys.stdout
    print(message, file=stream)


@dataclass
class _ParamInfo:
    kind: str
    default: object = None
    param_decls: tuple[str, ...] = field(default_factory=tuple)
    help: str = ""


def Option(default=None, *param_decls: str, help: str = ""):
    return _ParamInfo(kind="option", default=default, param_decls=param_decls, help=help)


def Argument(default=None, help: str = ""):
    return _ParamInfo(kind="argument", default=default, help=help)


class Typer:
    def __init__(self):
        self._command = None

    def command(self, *args, **kwargs):
        def decorator(func):
            self._command = func
            return func
        return decorator

    def __call__(self):
        if self._command is None:
            return

        parser = argparse.ArgumentParser()
        sig = inspect.signature(self._command)
        for name, param in sig.parameters.items():
            info = param.default
            annotation = param.annotation
            if not isinstance(info, _ParamInfo):
                info = _ParamInfo(kind="option", default=param.default)

            if info.kind == "argument":
                kwargs = {"help": info.help}
                if info.default is ...:
                    parser.add_argument(name, **kwargs)
                else:
                    parser.add_argument(name, nargs="?", default=info.default, **kwargs)
                continue

            option_names = info.param_decls or (f"--{name.replace('_', '-')}",)
            kwargs = {"dest": name, "help": info.help}
            if annotation is bool or isinstance(info.default, bool):
                kwargs["action"] = "store_true" if info.default is False else "store_false"
                kwargs["default"] = info.default
            else:
                if info.default is ...:
                    kwargs["required"] = True
                else:
                    kwargs["default"] = info.default
                if annotation is int:
                    kwargs["type"] = int
                elif annotation is float:
                    kwargs["type"] = float
                else:
                    kwargs["type"] = str
            parser.add_argument(*option_names, **kwargs)

        parsed = parser.parse_args()
        try:
            return self._command(**vars(parsed))
        except Exit as exc:
            raise SystemExit(exc.code) from None
