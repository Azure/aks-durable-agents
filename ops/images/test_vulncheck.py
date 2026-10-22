"""Exercise the strict packaged-Go scan with fake Docker/scanner boundaries."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("vulncheck.sh")


class ImageVulnerabilityTests(unittest.TestCase):
    def exercise(self, finding=False, missing=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docker = root / "docker"
            docker.write_text(f"#!{sys.executable}\n" + '''import os,pathlib,sys
args=sys.argv[1:]
with open(os.environ['TRACE'],'a') as log: log.write(' '.join(args)+'\\n')
if args[0]=='create': print('test-container')
elif args[0]=='cp':
    if os.environ.get('MISSING')=='true': sys.exit(1)
    pathlib.Path(args[2]).write_text('finding' if os.environ.get('FINDING')=='true' else 'clean')
elif args[0]!='rm': sys.exit(1)
''')
            scanner = root / "govulncheck"
            scanner.write_text(f"#!{sys.executable}\n" + '''import os,pathlib,sys
assert sys.argv[1]=='-mode=binary'
with open(os.environ['TRACE'],'a') as log: log.write('scan '+pathlib.Path(sys.argv[2]).name+'\\n')
sys.exit(3 if pathlib.Path(sys.argv[2]).read_text()=='finding' else 0)
''')
            docker.chmod(0o700)
            scanner.chmod(0o700)
            trace = root / "trace"
            result = subprocess.run(["bash", str(SCRIPT), "test/images", "test/helper@sha256:" + "a" * 64],
                env=dict(os.environ, PATH=directory + os.pathsep + os.environ["PATH"], TRACE=str(trace),
                         FINDING=str(finding).lower(), MISSING=str(missing).lower()), capture_output=True, text=True)
            return result, trace.read_text() if trace.exists() else ""

    def test_actual_packaged_binaries_all_scan_and_containers_are_removed(self):
        result, trace = self.exercise()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(trace.count('scan '), 5)
        self.assertEqual(trace.count('rm -f test-container'), 3)
        self.assertIn('test/helper@sha256:', trace)

    def test_own_image_advisory_blocks_and_container_is_removed(self):
        result, trace = self.exercise(finding=True)
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(trace.count('scan '), 1)
        self.assertIn('rm -f test-container', trace)

    def test_missing_packaged_binary_blocks_and_container_is_removed(self):
        result, trace = self.exercise(missing=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('scan ', trace)
        self.assertIn('rm -f test-container', trace)


if __name__ == "__main__":
    unittest.main()
