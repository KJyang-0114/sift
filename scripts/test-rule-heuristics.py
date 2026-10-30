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
        for candidate in ['os.system(command)', 'subprocess.run(command, shell=True)', 'child_process.exec(command)', 'shell_exec($command)']:  # nosemgrep -- inert regex fixture string; never executed
            self.assertIsNotNone(rule.search(candidate), candidate)

    def test_llm_calls(self):
        rule = pattern('prompt_injection.yaml')
        for safe in ['pool.run()', 'subprocess.run(args)', 'client.invoke()']:
            self.assertIsNone(rule.search(safe), safe)
        self.assertIsNotNone(rule.search('client.chat.completions.create(messages=messages)'))  # nosemgrep -- inert regex fixture string; never executed
        self.assertIsNotNone(rule.search('client.messages.create(messages=messages)'))  # nosemgrep -- inert regex fixture string; never executed

    def test_environment_file(self):
        rule = pattern('config_security.yaml', 1)
        for safe in ['os.environ', 'process.env.PORT', 'const secret = process.env.JWT_SECRET;']:
            self.assertIsNone(rule.search(safe), safe)
        for candidate in ['".env"', "'config/.env.production'", '`.env.local`']:  # nosemgrep -- inert regex fixture string; never executed
            self.assertIsNotNone(rule.search(candidate), candidate)

    def test_file_open(self):
        rule = pattern('path_traversal.yaml')
        for safe in ['tarfile.open(archive)', 'open("settings.json")', 'os.path.join(os.path.dirname(__file__), "static")',
                     'open(Path(__file__).parent / "x")', 'fs.readFileSync(path.join(__dirname, "a"))']:
            self.assertIsNone(rule.search(safe), safe)
        for candidate in ['open(user_path)', 'os.path.join(base, name)', 'fs.readFile(req.query.file)']:  # nosemgrep -- inert regex fixture string; never executed
            self.assertIsNotNone(rule.search(candidate), candidate)

    def test_error_leak(self):
        rule = pattern('error_handling.yaml')
        for safe in ['return err.Error()', "res.status(404).json({ error: 'Not found' })", 'http.Error(w, "internal", 500)']:
            self.assertIsNone(rule.search(safe), safe)
        for candidate in ['res.status(500).json({ error: err.message })', 'res.send(err)',  # nosemgrep -- inert regex fixture string; never executed
                          'http.Error(w, err.Error(), http.StatusInternalServerError)', 'return jsonify(error=str(e)), 500']:  # nosemgrep -- inert regex fixture string; never executed
            self.assertIsNotNone(rule.search(candidate), candidate)


if __name__ == '__main__':
    unittest.main()
