# SPDX-License-Identifier: Apache-2.0
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('release_boundaries', Path(__file__).with_name('release_tools.py'))
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)


class NetworkBoundaries(unittest.TestCase):
    def test_only_exact_approved_download_origins(self):
        for url in ('https://127.0.0.1/', 'https://169.254.169.254/latest/',
                    'https://github.com.attacker.example/file', 'https://attacker.example/',
                    'https://github.com:444/file', 'https://user:password@github.com/file',
                    'https://github.com/file#fragment', 'http://github.com/file'):
            with self.subTest(url=url), self.assertRaises(t.Refused):
                t.download_url(url)

    def test_network_paths_cannot_traverse(self):
        for path in ('/../secrets', '/%2e%2e/secrets', '/a/../../secrets', '/%252e%252e/secrets',
                     '/a%5c..%5csecrets', '/x%00y'):
            with self.subTest(path=path), self.assertRaises(t.Refused):
                t.download_url('https://github.com' + path)

    def test_api_cannot_change_origin_or_repository(self):
        for path in ('https://attacker.example/x', '//attacker.example/x', '/../../other-repo', '/x#y'):
            with self.subTest(path=path), self.assertRaises(t.Refused):
                t.api_url(t.TAP, path)
        with self.assertRaises(t.Refused):
            t.api_url('shoon/homebrew-tap/../../attacker', '/releases')

    def test_encoded_query_preserves_ref_as_data(self):
        actual = t.api_url(t.TAP, '/contents/Formula/a.rb?ref=release%2Fv1.2.3&per_page=100')
        self.assertEqual(actual, 'https://api.github.com/repos/shoon/homebrew-tap/contents/Formula/a.rb?ref=release%2Fv1.2.3&per_page=100')

    def test_redirect_cannot_leave_approved_hosts(self):
        request = t.urllib.request.Request('https://github.com/file')
        with self.assertRaises(t.Refused):
            t.SafeRedirect().redirect_request(request, None, 302, 'Found', {}, 'https://attacker.example/file')

    def test_docker_scope_is_query_data(self):
        actual = t.download_url('https://auth.docker.io/token?service=registry.docker.io&scope=repository:shoonimages/fv-ssh-unlock:pull')
        self.assertIn('scope=repository%3Ashoonimages%2Ffv-ssh-unlock%3Apull', actual)

    def test_path_delimiters_are_encoded(self):
        self.assertEqual(t.encoded_location('/a%3fb%23c'), '/a%3Fb%23c')

    def test_long_version_is_rejected_before_parsing(self):
        with self.assertRaises(t.Refused):
            t.version_key('v0.0.0--' + '.v0.0.0--' * 100_000)

    def test_non_ascii_version_components_rejected(self):
        for tag in ('v１.0.0', 'v1.0.0-réc', 'v1.0.0-', 'v1.0.0-rc..1'):
            with self.subTest(tag=tag), self.assertRaises(t.Refused):
                t.version_key(tag)


class RunnerFileBoundaries(unittest.TestCase):
    def test_arbitrary_runner_temp_is_not_trusted(self):
        with patch.dict(os.environ, {'RUNNER_TEMP': '/etc'}), self.assertRaises(t.Refused):
            t.hosted_temp()

    def test_expected_command_and_event_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / '_runner_file_commands').mkdir()
            (root / '_github_workflow').mkdir()
            output = root / '_runner_file_commands' / ('set_output_' + 'a' * 36)
            event = root / '_github_workflow' / 'event.json'
            env = {'RUNNER_TEMP': str(root), 'GITHUB_OUTPUT': str(output), 'GITHUB_EVENT_PATH': str(event)}
            with patch.dict(t.HOSTED_TEMP_ROOTS, {root.as_posix(): root.as_posix()}), patch.dict(os.environ, env):
                self.assertEqual(t.github_file('GITHUB_OUTPUT'), output)
                self.assertEqual(t.github_file('GITHUB_EVENT_PATH'), event)
                with patch.dict(os.environ, {'GITHUB_OUTPUT': str(root / 'arbitrary.txt')}), self.assertRaises(t.Refused):
                    t.github_file('GITHUB_OUTPUT')
                with patch.dict(os.environ, {'GITHUB_EVENT_PATH': str(root / 'secrets.json')}), self.assertRaises(t.Refused):
                    t.github_file('GITHUB_EVENT_PATH')

    @unittest.skipIf(os.name == 'nt', 'Unprivileged Windows symlinks may be unavailable')
    def test_command_file_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            folder = root / '_runner_file_commands'
            folder.mkdir()
            output = folder / ('set_output_' + 'b' * 36)
            output.symlink_to(root / 'outside-command-directory.txt')
            with patch.dict(t.HOSTED_TEMP_ROOTS, {root.as_posix(): root.as_posix()}), patch.dict(os.environ, {'RUNNER_TEMP': str(root), 'GITHUB_OUTPUT': str(output)}), self.assertRaises(t.Refused):
                t.github_file('GITHUB_OUTPUT')


if __name__ == '__main__':
    unittest.main()
