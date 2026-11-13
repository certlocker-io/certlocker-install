"""Secret and line prompts that work when only /dev/tty is interactive.

stdin.isatty() is often false under wrappers (IDE terminals, controller
attach quirks) even though the operator still has a controlling terminal.
Hidden prompts must use that terminal instead of silently failing.
"""
from contextlib import contextmanager, nullcontext
import getpass
import sys
import warnings


def can_prompt(non_interactive=False):
    """True when the operator can answer hidden or interactive prompts."""
    if non_interactive:
        return False
    if sys.stdin.isatty():
        return True
    try:
        with open('/dev/tty', 'r+', buffering=1):
            return True
    except OSError:
        return False


def _format_missing(env_name):
    if env_name:
        return f'set {env_name} for unattended setup, or rerun in a terminal'
    return 'rerun in a terminal that can accept hidden input'


def _quiet(progress):
    if progress is not None and hasattr(progress, 'quiet'):
        return progress.quiet()
    return nullcontext()


def prompt_secret(message, *, env_name=None, progress=None):
    """Prompt on the controlling terminal; never echo the value."""
    label = message.rstrip()
    if not label.endswith(':'):
        label += ':'
    if not can_prompt():
        raise ValueError(f'{label.rstrip(":")} was not available; {_format_missing(env_name)}')
    with _quiet(progress):
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            tty = None
            try:
                try:
                    tty = open('/dev/tty', 'w+', buffering=1)
                except OSError:
                    tty = None
                if tty is not None:
                    print(label + ' ', file=tty, end='', flush=True)
                    value = getpass.getpass('', stream=tty).strip()
                else:
                    value = getpass.getpass(label + ' ').strip()
            except getpass.GetPassWarning as error:
                raise ValueError(
                    f'A terminal with hidden input is required; {_format_missing(env_name)}'
                ) from error
            finally:
                if tty is not None:
                    tty.close()
    if not value:
        raise ValueError(f'{label.rstrip(":")} was empty; {_format_missing(env_name)}')
    return value


def prompt_line(message, default=None, *, progress=None):
    """Read a non-secret line from the controlling terminal when possible."""
    if not can_prompt():
        if default is not None:
            return default
        raise ValueError(f'{message.rstrip(": ")} requires a terminal or a saved config value')
    shown = message.rstrip() + (f' [{default}]' if default is not None else '') + ': '
    with _quiet(progress):
        tty = None
        try:
            try:
                tty = open('/dev/tty', 'r+', buffering=1)
            except OSError:
                tty = None
            if tty is not None:
                print(shown, file=tty, end='', flush=True)
                value = tty.readline().strip()
            else:
                value = input(shown).strip()
        finally:
            if tty is not None:
                tty.close()
    return value or default
