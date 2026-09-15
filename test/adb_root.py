"""Root shell selection for isolated device regressions (root adbd or Magisk su)."""
import shlex
import subprocess


def root_command(adb):
    result = subprocess.run(adb + ['shell', 'id', '-u'], check=True,
                            capture_output=True, text=True, timeout=15)
    if result.stdout.strip() == '0':
        return lambda command: command
    return lambda command: 'su -c ' + shlex.quote(command)
