"""Regression checks for the lexical patterns narrowed in v1.5.

These checks cover regex matching, not Semgrep parsing or vulnerability accuracy.
"""
from pathlib import Path
import re
import unittest

RULES = Path(__file__).resolve().parents[1] / 'internal/static/rules'


def pattern(filename, index=0):
    patterns = [line.split('pattern-regex:', 1)[1].strip()
                for line in (RULES / filename).read_text().splitlines()
                if 'pattern-regex:' in line]
    return re.compile(patterns[index])


class RuleRegressionTests(unittest.TestCase):
    def test_shell_calls(self):
        rule = pattern('command_injection.yaml')
        for safe in ['import subprocess', 'subprocess.run(["go", "build"], check=True)', 'child_process.execFile("tool", args)']:
            self.assertIsNone(rule.search(safe), safe)
        for candidate in ['os.system(command)', 'subprocess.run(command, shell=True)', 'child_process.exec(command)', 'shell_exec($command)']:
            self.assertIsNotNone(rule.search(candidate), candidate)

    def test_llm_calls(self):
        rule = pattern('prompt_injection.yaml')
        for safe in ['pool.run()', 'subprocess.run(args)', 'client.invoke()']:
            self.assertIsNone(rule.search(safe), safe)
        self.assertIsNotNone(rule.search('client.chat.completions.create(messages=messages)'))
        self.assertIsNotNone(rule.search('client.messages.create(messages=messages)'))

    def test_environment_file(self):
        rule = pattern('config_security.yaml', 1)
        self.assertIsNone(rule.search('os.environ'))
        self.assertIsNotNone(rule.search('".env"'))

    def test_file_open(self):
        rule = pattern('path_traversal.yaml')
        self.assertIsNone(rule.search('tarfile.open(archive)'))
        self.assertIsNotNone(rule.search('open(user_path)'))


if __name__ == '__main__':
    unittest.main()
