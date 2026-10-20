"""Exercise real Git histories for pin updates and interrupted-PR retries."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_update_pins import VALUES, manifest

SCRIPT = Path(__file__).with_name("open_pin_pr.sh").resolve()


class PinBranchTests(unittest.TestCase):
    def test_updates_one_branch_without_force_and_recovers_after_push(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote, repo = root / "remote.git", root / "repo"
            subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
            repo.mkdir()
            def git(*args):
                return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()
            git("init", "-b", "main")
            git("config", "user.name", "Test Author")
            git("config", "user.email", "test@example.invalid")
            git("remote", "add", "origin", str(remote))
            values = repo / "charts/aks-durable-agents/values.yaml"
            values.parent.mkdir(parents=True)
            values.write_text(VALUES)
            # The real updater is invoked from the same relative location as CI.
            updater = repo / "ops/images/update_pins.py"
            updater.parent.mkdir(parents=True)
            updater.write_bytes(Path(__file__).with_name("update_pins.py").read_bytes())
            git("add", ".")
            git("commit", "-m", "initial")
            git("push", "-u", "origin", "main")
            gh = root / "bin/gh"
            gh.parent.mkdir()
            gh.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
state=pathlib.Path(os.environ['GH_TEST_STATE'])
command=sys.argv[1:3]
if command==['pr','list']:
    print('7' if state.exists() else '')
elif command==['pr','create']:
    if os.environ.get('GH_TEST_FAIL_CREATE')=='yes': sys.exit(1)
    state.write_text(json.dumps(sys.argv[1:]))
elif command==['pr','edit']:
    state.write_text(json.dumps(sys.argv[1:]))
else: sys.exit(2)
''')
            gh.chmod(0o700)
            publication = root / "images.json"
            data = manifest()
            data["sourceCommit"] = git("rev-parse", "HEAD")
            publication.write_text(json.dumps(data))
            environment = dict(os.environ, PATH=str(gh.parent) + os.pathsep + os.environ["PATH"], SOURCE=data["sourceCommit"], MANIFEST=str(publication), GH_TEST_STATE=str(root / "pr.json"))
            def run(fail=False):
                env = dict(environment, GH_TEST_FAIL_CREATE="yes" if fail else "no")
                return subprocess.run(["bash", str(SCRIPT)], cwd=repo, env=env, capture_output=True, text=True)
            # A failure after push must leave a usable branch, not require deletion.
            result = run(fail=True)
            self.assertNotEqual(result.returncode, 0)
            git("fetch", "origin")
            exists = subprocess.run(["git", "-C", str(repo), "show-ref", "--quiet", "refs/remotes/origin/automation/image-pins"])
            self.assertEqual(exists.returncode, 0, result.stderr)
            first = git("rev-parse", "origin/automation/image-pins")
            git("switch", "main")
            result = run()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(git("rev-parse", "origin/automation/image-pins"), first)
            self.assertTrue((root / "pr.json").exists())
            # A newer publication updates the same branch with normal ancestry.
            git("switch", "main")
            (repo / "source.txt").write_text("next image source\n")
            git("add", "source.txt")
            git("commit", "-m", "next source")
            git("push", "origin", "main")
            data["sourceCommit"] = git("rev-parse", "HEAD")
            data["images"]["host"]["digest"] = "sha256:" + "3" * 64
            publication.write_text(json.dumps(data))
            environment["SOURCE"] = data["sourceCommit"]
            result = run()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            second = git("rev-parse", "origin/automation/image-pins")
            self.assertNotEqual(first, second)
            git("merge-base", "--is-ancestor", first, second)
            self.assertEqual(git("diff", "--name-only", "origin/main", second), "charts/aks-durable-agents/values.yaml")
            self.assertIn("sha256:" + "3" * 64, values.read_text())
            self.assertEqual(json.loads((root / "pr.json").read_text())[0:2], ["pr", "edit"])
            # Never overwrite a reserved branch that acquired unrelated work.
            (repo / "unrelated.txt").write_text("not image pins\n")
            git("add", "unrelated.txt")
            git("commit", "-m", "unrelated branch work")
            git("push", "origin", "HEAD:refs/heads/automation/image-pins")
            git("switch", "main")
            result = run()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Refusing automation branch with unrelated changes", result.stderr)


if __name__ == "__main__":
    unittest.main()
