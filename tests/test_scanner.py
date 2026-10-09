"""Tests for guardlib.scanner.

No real credentials appear here. Every fixture value is synthetic and built so
that it matches a rule's shape without being a usable secret.
"""

import base64
import contextlib
import hashlib
import io
import os
import shutil
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from guardlib import scanner  # noqa: E402


# Synthetic fixtures. Shapes are real; values are not.
FAKE_AWS_ID = "AKIA" + "Q" * 16
FAKE_GITHUB_PAT = "ghp_" + "b" * 36
FAKE_SLACK = "xoxb-1111111111-2222222222-" + "c" * 24
FAKE_ANTHROPIC = "sk-ant-" + "d" * 32
FAKE_OPENAI = "sk-" + "e" * 32
FAKE_GOOGLE = "AIza" + "f" * 35
FAKE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIwMDAwIiwibmFtZSI6InRlc3QifQ."
    + "g" * 32
)
HIGH_ENTROPY = "Zm9vYmFy" + "Qx7Tz9Lp2Wv4Nk8Rb3Yd6Hs1Jm5"


class RedactionTests(unittest.TestCase):
    def test_short_values_reveal_nothing(self):
        self.assertEqual(scanner.redact("hunter2"), "<redacted len=7>")
        self.assertNotIn("hunter", scanner.redact("hunter2"))

    def test_boundary_at_eight_characters(self):
        self.assertEqual(scanner.redact("a" * 8), "<redacted len=8>")
        self.assertTrue(scanner.redact("a" * 9).startswith("aaaa..."))

    def test_long_values_expose_only_a_prefix(self):
        secret = "ABCD" + "z" * 40
        out = scanner.redact(secret)
        self.assertIn("len=44", out)
        self.assertNotIn(secret, out)
        self.assertEqual(out.count("z"), 0)

    def test_findings_never_carry_the_full_secret(self):
        """The security property: no code path emits the whole value."""
        samples = [
            f"key = {FAKE_AWS_ID}",
            f"token={FAKE_GITHUB_PAT}",
            f"SLACK_TOKEN={FAKE_SLACK}",
            f"ANTHROPIC_API_KEY={FAKE_ANTHROPIC}",
            f"OPENAI_API_KEY={FAKE_OPENAI}",
            f"GOOGLE_API_KEY={FAKE_GOOGLE}",
            f"Authorization: Bearer {FAKE_GITHUB_PAT}",
            f"DB_PASSWORD={'p' * 24}",
        ]
        secrets = [
            FAKE_AWS_ID,
            FAKE_GITHUB_PAT,
            FAKE_SLACK,
            FAKE_ANTHROPIC,
            FAKE_OPENAI,
            FAKE_GOOGLE,
            "p" * 24,
        ]
        text = "\n".join(samples)
        findings = scanner.scan_text(text, path="fixture.env")
        self.assertTrue(findings, "expected findings for the fixture block")
        rendered = "\n".join(f.format() for f in findings)
        for secret in secrets:
            with self.subTest(secret=secret[:6]):
                self.assertNotIn(secret, rendered)
        # Nor on the dataclass itself.
        for finding in findings:
            for secret in secrets:
                self.assertNotIn(secret, finding.redacted)


class NamedRuleTests(unittest.TestCase):
    def _ids(self, text):
        return {f.rule_id for f in scanner.scan_text(text)}

    def test_private_key_block(self):
        text = "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nbody\n"
        self.assertIn("private_key_block", self._ids(text))

    def test_private_key_block_without_algorithm(self):
        self.assertIn("private_key_block", self._ids("-----BEGIN " + "PRIVATE KEY-----"))

    def test_aws_access_key_id(self):
        self.assertIn("aws_access_key_id", self._ids(f"id: {FAKE_AWS_ID}"))

    def test_github_pat(self):
        self.assertIn("github_pat", self._ids(f"pat {FAKE_GITHUB_PAT}"))

    def test_github_fine_grained_pat(self):
        token = "github_pat_" + "h" * 40
        self.assertIn("github_fine_grained_pat", self._ids(token))

    def test_slack_token(self):
        self.assertIn("slack_token", self._ids(FAKE_SLACK))

    def test_anthropic_key_is_not_reported_as_openai(self):
        ids = self._ids(FAKE_ANTHROPIC)
        self.assertIn("anthropic_api_key", ids)
        self.assertNotIn("openai_api_key", ids)

    def test_openai_key(self):
        self.assertIn("openai_api_key", self._ids(FAKE_OPENAI))

    def test_google_api_key(self):
        self.assertIn("google_api_key", self._ids(FAKE_GOOGLE))

    def test_jwt(self):
        self.assertIn("jwt", self._ids(f"Cookie: {FAKE_JWT}"))

    def test_bearer_token(self):
        self.assertIn("bearer_token", self._ids(f"Authorization: Bearer {'k' * 32}"))

    def test_dotenv_secret(self):
        text = "export DATABASE_PASSWORD='s3cr3tvalue123'"
        self.assertIn("dotenv_secret", self._ids(text))

    def test_dotenv_secret_matches_api_key_spelling(self):
        self.assertIn("dotenv_secret", self._ids("API_KEY=" + "abcdef123456"))

    def test_password_assignment_in_code(self):
        text = 'conn = connect(password="correct-horse-battery")'
        self.assertIn("password_assignment", self._ids(text))

    def test_url_embedded_credential(self):
        text = "postgres://user:supersecret@db.internal:5432/app"
        self.assertIn("url_embedded_credential", self._ids(text))

    def test_rule_reports_path_and_line(self):
        text = "clean line\nanother clean line\n" + f"key={FAKE_AWS_ID}\n"
        findings = scanner.scan_text(text, path="conf/app.env")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].path, "conf/app.env")
        self.assertEqual(findings[0].line, 3)

    def test_severity_is_carried(self):
        findings = scanner.scan_text(f"id {FAKE_AWS_ID}")
        self.assertEqual(findings[0].severity, "critical")


class NegativeTests(unittest.TestCase):
    """Clean input must stay clean: a scanner that flags everything is useless."""

    def _ids(self, text, config=None):
        return {f.rule_id for f in scanner.scan_text(text, config=config)}

    def test_ordinary_prose_is_clean(self):
        text = textwrap.dedent(
            """
            The quick brown fox jumps over the lazy dog. This paragraph talks
            about passwords and tokens in the abstract without containing any.
            """
        )
        self.assertEqual(self._ids(text), set())

    def test_placeholder_values_are_ignored(self):
        for value in ("changeme", "${DB_PASSWORD}", "xxxxxxxx", "<your_token_here>"):
            with self.subTest(value=value):
                self.assertEqual(self._ids(f"PASSWORD={value}"), set())

    def test_interpolated_shell_variable_is_ignored(self):
        self.assertEqual(self._ids("export API_KEY=$CI_API_KEY"), set())

    def test_short_password_is_not_matched(self):
        self.assertEqual(self._ids("PASSWORD=abc"), set())

    def test_lowercase_word_is_not_high_entropy(self):
        text = "supercalifragilisticexpialidocious_and_then_some_more_words"
        self.assertEqual(self._ids(text), set())

    def test_hex_digest_is_not_flagged_by_default(self):
        digest = "a" * 8 + "b3f1c2d4e5f60718293a4b5c6d7e8f90" + "1234"
        self.assertNotIn("high_entropy_hex", self._ids(digest))

    def test_hex_digest_flagged_only_when_requested(self):
        # 48 hex characters: long enough for --flag-hex, and not the 40 or 64
        # of a SHA-1 or SHA-256 digest, which is exempt by shape.
        value = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822c"
        config = scanner.ScanConfig(
            entropy=scanner.EntropyConfig(flag_hex=True)
        )
        self.assertIn("high_entropy_hex", self._ids(value, config))

    def test_entropy_detector_can_be_disabled(self):
        config = scanner.ScanConfig(entropy=scanner.EntropyConfig(enabled=False))
        self.assertNotIn("high_entropy_base64", self._ids(HIGH_ENTROPY, config))


class EntropyTests(unittest.TestCase):
    def test_entropy_of_uniform_string_is_zero(self):
        self.assertEqual(scanner.shannon_entropy("aaaaaaaa"), 0.0)

    def test_entropy_of_empty_string_is_zero(self):
        self.assertEqual(scanner.shannon_entropy(""), 0.0)

    def test_two_symbols_balanced_is_one_bit(self):
        self.assertAlmostEqual(scanner.shannon_entropy("abab"), 1.0)

    def test_entropy_rises_with_variety(self):
        low = scanner.shannon_entropy("aaaabbbb")
        high = scanner.shannon_entropy("abcdefgh")
        self.assertLess(low, high)

    def test_high_entropy_token_is_reported(self):
        findings = scanner.scan_text(f"blob = {HIGH_ENTROPY}")
        self.assertIn("high_entropy_base64", {f.rule_id for f in findings})

    def test_entropy_finding_is_medium_severity(self):
        findings = [
            f
            for f in scanner.scan_text(HIGH_ENTROPY)
            if f.rule_id == "high_entropy_base64"
        ]
        self.assertEqual(findings[0].severity, "medium")


class SuppressionTests(unittest.TestCase):
    def test_inline_marker_suppresses_the_line(self):
        text = f"key = {FAKE_AWS_ID}  # {scanner.SUPPRESS_MARKER} test fixture"
        self.assertEqual(scanner.scan_text(text), [])

    def test_suppression_can_be_ignored(self):
        text = f"key = {FAKE_AWS_ID}  # {scanner.SUPPRESS_MARKER}"
        config = scanner.ScanConfig(honor_suppressions=False)
        self.assertTrue(scanner.scan_text(text, config=config))

    def test_suppression_only_affects_its_own_line(self):
        text = (
            f"a = {FAKE_AWS_ID}  # {scanner.SUPPRESS_MARKER}\n"
            f"b = {FAKE_GITHUB_PAT}\n"
        )
        findings = scanner.scan_text(text)
        self.assertEqual([f.line for f in findings], [2])


class FileAndTreeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="guard-scan-")
        self.root = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def _write(self, relpath, content, mode="w"):
        full = os.path.join(self.root, relpath)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, mode) as handle:
            handle.write(content)
        return full

    def test_scan_file_reports_relative_findings(self):
        path = self._write("app/.env", f"SECRET_KEY={'z' * 30}\n")
        findings = scanner.scan_file(path)
        self.assertTrue(findings)
        self.assertEqual(findings[0].path, path)

    def test_scan_file_on_missing_path_is_empty(self):
        self.assertEqual(scanner.scan_file(os.path.join(self.root, "nope")), [])

    def test_binary_file_is_skipped(self):
        path = os.path.join(self.root, "blob.bin")
        with open(path, "wb") as handle:
            handle.write(b"\x00\x01\x02" + FAKE_AWS_ID.encode() + b"\x00")
        self.assertEqual(scanner.scan_file(path), [])

    def test_skipped_suffix_is_not_scanned(self):
        path = self._write("logo.png", f"key={FAKE_AWS_ID}")
        self.assertEqual(scanner.scan_file(path), [])

    def test_oversized_file_is_skipped(self):
        path = self._write("big.txt", "x")
        config = scanner.ScanConfig(max_file_bytes=0)
        self.assertEqual(scanner.scan_file(path, config), [])

    def test_walk_finds_nested_secrets(self):
        self._write("a/b/c/.env", f"API_KEY={'q' * 24}\n")
        self._write("a/readme.txt", "nothing here\n")
        findings = scanner.scan_path(self.root)
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].path.endswith(os.path.join("a", "b", "c", ".env")))

    def test_walk_skips_default_directories(self):
        self._write("node_modules/pkg/index.js", f"const k = '{FAKE_AWS_ID}';\n")
        self._write(".git/config", f"token = {FAKE_GITHUB_PAT}\n")
        self.assertEqual(scanner.scan_path(self.root), [])

    def test_walk_is_deterministic(self):
        for name in ("z.env", "a.env", "m.env"):
            self._write(name, f"SECRET={name}longenoughvalue\n")
        first = [f.path for f in scanner.scan_path(self.root)]
        second = [f.path for f in scanner.scan_path(self.root)]
        self.assertEqual(first, second)
        self.assertEqual(first, sorted(first))

    def test_symlink_is_not_followed_by_default(self):
        target = self._write("real/.env", f"SECRET_KEY={'y' * 30}\n")
        link = os.path.join(self.root, "link.env")
        os.symlink(target, link)
        self.assertEqual(scanner.scan_file(link), [])

    def test_scan_path_accepts_a_single_file(self):
        path = self._write("solo.env", f"API_KEY={'r' * 24}\n")
        self.assertTrue(scanner.scan_path(path))

    def test_unreadable_file_is_skipped_not_fatal(self):
        path = self._write("locked.env", f"API_KEY={'s' * 24}\n")
        os.chmod(path, 0o000)
        self.addCleanup(os.chmod, path, 0o600)
        self.assertEqual(scanner.scan_file(path), [])


class SeverityAggregationTests(unittest.TestCase):
    def test_worst_severity_of_empty_is_none(self):
        self.assertIsNone(scanner.worst_severity([]))

    def test_worst_severity_picks_critical(self):
        findings = scanner.scan_text(
            f"a={FAKE_AWS_ID}\nb = {HIGH_ENTROPY}\n"
        )
        self.assertEqual(scanner.worst_severity(findings), "critical")

    def test_worst_severity_of_medium_only(self):
        findings = scanner.scan_text(f"b = {HIGH_ENTROPY}\n")
        self.assertEqual(scanner.worst_severity(findings), "medium")


class CliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="guard-cli-")
        self.root = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def _run(self, argv):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = scanner.main(argv)
        return code, buffer.getvalue()

    def test_exit_code_zero_on_clean_tree(self):
        with open(os.path.join(self.root, "ok.txt"), "w") as handle:
            handle.write("all clear\n")
        code, out = self._run([self.root])
        self.assertEqual(code, 0)
        self.assertIn("0 finding(s)", out)

    def test_exit_code_one_on_finding(self):
        with open(os.path.join(self.root, "bad.env"), "w") as handle:
            handle.write(f"API_KEY={'t' * 24}\n")
        code, out = self._run([self.root])
        self.assertEqual(code, 1)
        self.assertIn("dotenv_secret", out)

    def test_cli_output_does_not_contain_the_secret(self):
        secret = "u" * 28
        with open(os.path.join(self.root, "bad.env"), "w") as handle:
            handle.write(f"API_KEY={secret}\n")
        _, out = self._run([self.root])
        self.assertNotIn(secret, out)

    def test_no_entropy_flag_disables_entropy_rule(self):
        with open(os.path.join(self.root, "blob.txt"), "w") as handle:
            handle.write(HIGH_ENTROPY + "\n")
        _, with_entropy = self._run([self.root])
        _, without = self._run(["--no-entropy", self.root])
        self.assertIn("high_entropy_base64", with_entropy)
        self.assertNotIn("high_entropy_base64", without)



class SuppressionCommentTests(unittest.TestCase):
    """The marker silences a line only from inside a comment."""

    def test_marker_inside_a_quoted_url_does_not_suppress(self):
        for line in ('password = "https://example.com//guard:allow"',
                     "password = 'x;guard:allow'",
                     'password = "s3cr3tValue123 # guard:allow"'):
            with self.subTest(line=line):
                self.assertFalse(scanner.is_suppressed(line))
                self.assertTrue(scanner.scan_text(line))

    def test_comment_markers_suppress(self):
        for line in ('password = "s3cr3tValue123"  # guard:allow',
                     'password = "s3cr3tValue123"; // guard:allow',
                     'password = "s3cr3tValue123" /* guard:allow */',
                     "password = 's3cr3tValue123' -- guard:allow",
                     'msg = "it\\"s"  # guard:allow'):
            with self.subTest(line=line):
                self.assertTrue(scanner.is_suppressed(line))

    def test_url_slashes_are_not_a_comment(self):
        self.assertFalse(scanner.is_suppressed("url = https://host/guard:allow"))


class LongLineTests(unittest.TestCase):
    """A minified JSON or JSONL line can carry a secret past byte 8192."""

    def test_secret_far_past_the_window_is_found(self):
        secret = FAKE_GITHUB_PAT
        line = '{"pad":"' + ("a" * 40000) + '","token":"' + secret + '"}'
        findings = scanner.scan_text(line)
        self.assertTrue(
            any(f.rule_id == "github_pat" for f in findings),
            "a secret past the first window was missed",
        )

    def test_secret_in_every_window_is_reported_once(self):
        secret = FAKE_GITHUB_PAT
        line = "x" * 20000 + " " + secret + " " + "y" * 20000
        hits = [f for f in scanner.scan_text(line) if f.rule_id == "github_pat"]
        self.assertEqual(len(hits), 1)

    def test_secret_straddling_a_window_edge_is_found(self):
        secret = FAKE_GITHUB_PAT
        # Place the token so it begins a few characters before the first
        # window ends, which truncation and naive chunking both miss.
        prefix = "z" * (scanner.MAX_LINE_BYTES - 5) + " "
        findings = scanner.scan_text(prefix + secret + " tail")
        self.assertTrue(any(f.rule_id == "github_pat" for f in findings))

    def test_every_offset_near_the_edge_is_covered(self):
        step = scanner.MAX_LINE_BYTES - scanner.LINE_CHUNK_OVERLAP
        for offset in (
            step - 1,
            step,
            step + 1,
            scanner.MAX_LINE_BYTES - len(FAKE_GITHUB_PAT),
            scanner.MAX_LINE_BYTES,
            scanner.MAX_LINE_BYTES + 1,
            2 * step + 7,
        ):
            with self.subTest(offset=offset):
                line = "q" * offset + " " + FAKE_GITHUB_PAT
                hits = [
                    f for f in scanner.scan_text(line) if f.rule_id == "github_pat"
                ]
                self.assertEqual(len(hits), 1)

    def test_line_numbers_survive_chunking(self):
        text = "first\n" + ("p" * 20000) + " " + FAKE_GITHUB_PAT + "\nthird\n"
        findings = [f for f in scanner.scan_text(text) if f.rule_id == "github_pat"]
        self.assertEqual([f.line for f in findings], [2])

    def test_chunk_windows_cover_the_whole_line(self):
        line = "c" * (3 * scanner.MAX_LINE_BYTES + 11)
        covered = 0
        for _, accept in scanner.line_chunks(line):
            covered += accept
        self.assertEqual(covered, len(line))

    def test_short_line_is_a_single_window(self):
        self.assertEqual(list(scanner.line_chunks("abc")), [("abc", 3)])


class DollarValueTests(unittest.TestCase):
    """A leading "$" is not by itself a sign of shell interpolation."""

    BCRYPT = "$2b$12$KIXxVfQ8ZqLpR3nTuWieJmHgYcAdBfEsNkQwLzXrPvTyUoIaBcDe"

    def test_bcrypt_hash_assignment_is_reported(self):
        findings = scanner.scan_text(f"PASSWORD_HASH={self.BCRYPT}")
        self.assertTrue(findings, "a bcrypt hash was skipped as interpolation")

    def test_password_beginning_with_a_dollar_is_reported(self):
        findings = scanner.scan_text('password = "$up3rS3cretValue!"')
        self.assertTrue(findings)

    def test_interpolation_shapes_are_still_skipped(self):
        for value in ("${GITHUB_TOKEN}", "$GITHUB_TOKEN", "${_private}"):
            with self.subTest(value=value):
                self.assertTrue(scanner._is_placeholder(value))

    def test_dollar_shapes_that_are_not_interpolation(self):
        # "$word" is left as interpolation: it is exactly the shape of $VAR and
        # nothing in the value separates the two. Only shapes that cannot be a
        # variable name are treated as literals.
        for value in (self.BCRYPT, "$2y$10$abcdef", "$1-$2", "$up3r-S3cret"):
            with self.subTest(value=value):
                self.assertFalse(scanner._is_placeholder(value))

    def test_env_file_with_interpolation_is_clean(self):
        findings = scanner.scan_text("API_TOKEN=${CI_API_TOKEN}\n")
        self.assertEqual(findings, [])


class CommentSuppressionTests(unittest.TestCase):
    def test_hash_comment_suppresses(self):
        line = f"token = '{FAKE_GITHUB_PAT}'  # guard:allow fixture"
        self.assertEqual(scanner.scan_text(line), [])

    def test_slash_comment_suppresses(self):
        line = f'const t = "{FAKE_GITHUB_PAT}"; // guard:allow fixture'
        self.assertEqual(scanner.scan_text(line), [])

    def test_marker_inside_a_string_value_does_not_suppress(self):
        line = f'note = "guard:allow"; token = "{FAKE_GITHUB_PAT}"'
        findings = scanner.scan_text(line)
        self.assertTrue(
            any(f.rule_id == "github_pat" for f in findings),
            "a quoted marker must not silence the line",
        )

    def test_marker_as_a_bare_word_does_not_suppress(self):
        line = f"guard:allow {FAKE_GITHUB_PAT}"
        self.assertTrue(scanner.scan_text(line))

    def test_suppressed_lines_are_counted(self):
        stats = scanner.ScanStats()
        text = (
            f"a = '{FAKE_GITHUB_PAT}'  # guard:allow\n"
            "plain line\n"
            f"b = '{FAKE_AWS_ID}'  // guard:allow\n"
        )
        findings = scanner.scan_text(text, stats=stats)
        self.assertEqual(findings, [])
        self.assertEqual(stats.suppressed_lines, 2)
        self.assertEqual(stats.lines_scanned, 3)

    def test_ignore_suppressions_still_reports_and_does_not_count(self):
        stats = scanner.ScanStats()
        config = scanner.ScanConfig(honor_suppressions=False)
        line = f"a = '{FAKE_GITHUB_PAT}'  # guard:allow"
        findings = scanner.scan_text(line, config=config, stats=stats)
        self.assertTrue(findings)
        self.assertEqual(stats.suppressed_lines, 0)

    def test_cli_prints_the_suppression_count(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        with open(os.path.join(root, "a.py"), "w", encoding="utf-8") as handle:
            handle.write(f"t = '{FAKE_GITHUB_PAT}'  # guard:allow\nx = 1\n")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = scanner.main([root])
        out = buffer.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("1 line(s) suppressed", out)
        self.assertNotIn(FAKE_GITHUB_PAT, out)


class AdditionalTokenShapeTests(unittest.TestCase):
    CASES = (
        ("stripe_live_key", "sk_" + "live_51HxQ9mN2kR7tW4yU6nH1jF8dS5gV"),
        ("stripe_live_key", "rk_" + "live_51HxQ9mN2kR7tW4yU6nH1jF8dS5gV"),
        ("gitlab_pat", "glpat-" + "xK9mQ2vR7tL4wP8nB3zY"),
        ("npm_token", "npm_" + "aB3xQ9zLmP2kR7tW4yU6nH1jF8dS5gV0cX7e"),
        ("huggingface_token", "hf_" + "qRtYuIoPaSdFgHjKlZxCvBnMqWeRtY"),
    )

    def test_each_shape_is_detected(self):
        for rule_id, token in self.CASES:
            with self.subTest(rule_id=rule_id):
                findings = scanner.scan_text(f"value = '{token}'")
                self.assertIn(rule_id, [f.rule_id for f in findings])

    def test_each_shape_is_critical(self):
        for rule_id, token in self.CASES:
            with self.subTest(rule_id=rule_id):
                hits = [
                    f for f in scanner.scan_text(token) if f.rule_id == rule_id
                ]
                self.assertEqual([f.severity for f in hits], ["critical"])

    def test_no_shape_leaks_its_token(self):
        for rule_id, token in self.CASES:
            with self.subTest(rule_id=rule_id):
                for finding in scanner.scan_text(token):
                    self.assertNotIn(token, finding.format())

    def test_near_misses_are_not_reported_under_the_new_rules(self):
        new_rules = {rule_id for rule_id, _ in self.CASES}
        negatives = (
            "sk_" + "test_51HxQ9mN2kR7tW4yU6nH1jF8dS5gV",  # test key, not live
            "glpat-short",
            "npm_tooShort",
            "hf_short",
            "prefix_sk_live",
        )
        for value in negatives:
            with self.subTest(value=value):
                hit = [
                    f.rule_id
                    for f in scanner.scan_text(value)
                    if f.rule_id in new_rules
                ]
                self.assertEqual(hit, [])

    def test_npm_token_requires_the_exact_length(self):
        self.assertEqual(
            [
                f.rule_id
                for f in scanner.scan_text("npm_" + "a" * 35)
                if f.rule_id == "npm_token"
            ],
            [],
        )


class MappingSecretTests(unittest.TestCase):
    def test_yaml_mapping_secret_is_reported(self):
        line = "aws_secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        self.assertIn(
            "mapping_secret", [f.rule_id for f in scanner.scan_text(line)]
        )

    def test_json_mapping_secret_is_reported(self):
        line = '  "api_key": ' + '"abc123def456ghi789",'
        self.assertIn(
            "mapping_secret", [f.rule_id for f in scanner.scan_text(line)]
        )

    def test_list_item_mapping_secret_is_reported(self):
        self.assertIn(
            "mapping_secret",
            [f.rule_id for f in scanner.scan_text("- secret: s3cr3tValue123")],
        )

    def test_mapping_secret_redacts(self):
        line = '  "api_key": ' + '"abc123def456ghi789",'
        for finding in scanner.scan_text(line):
            self.assertNotIn("abc123def456ghi789", finding.format())

    def test_code_valued_mappings_are_not_reported(self):
        """Observed in packages/: the value is a variable, not a literal."""
        for line in (
            "          max_tokens: maxTokens,",
            "        credential: Object.freeze({",
            "    credential: assignment.credential,",
            '          credential_relationship: "uses-credential"',
            '    "tokenUnit": ' + '"utf8_bytes_upper_bound"',
            "          credential_bindings: agent.credential_bindings,",
        ):
            with self.subTest(line=line.strip()):
                self.assertEqual(
                    [
                        f.rule_id
                        for f in scanner.scan_text(line)
                        if f.rule_id == "mapping_secret"
                    ],
                    [],
                )

    def test_placeholder_and_interpolated_mappings_are_clean(self):
        for line in ("token: ${GITHUB_TOKEN}", "password: changeme", "key: value"):
            with self.subTest(line=line):
                self.assertEqual(scanner.scan_text(line), [])


class EntropyFalsePositiveTests(unittest.TestCase):
    """Regression set drawn from scanning this repository's docs/ and packages/.

    Before these exemptions the entropy detector reported 68,799 findings over
    1,863 files; 98% of them were absolute paths. Each string below is a
    verbatim token from that run.
    """

    OBSERVED = (
        "/Users/AliceExample/AppData/Local/Temp/context-import-mutations-wu5G5z"
        "/snapshot/node_modules/typescript/lib",
        "1/AppData/Local/Temp/context-import-mutations-SYklUF/evidence",
        "exampleco-docs/plan/EXAMPLECO-CRITICAL-PATH-AND-MASTER-BACKLOG-2026-09-01",
        "packages/context-import/src/store",
        "context-import-mutations-EawyPg",
        "context-import-mutations-SYklUF",
        "AlphaAssignmentOutcomeUnknownError",
        "validateSubmissionArtifactForPublisher",
        "asyncRunEntryPointWithESMLoader",
        "NodeUnixAssignmentSocketTransport",
        "Ctx014DispatchAuthorityError",
        "assertCtx029AssignmentRuntimeConfig",
        "10-claude-fallback-dropped-beside-nontext",
        "21-per-request-capabilities-guard-removed",
        "38-watch-immutable-snapshot-discarded",
        "abc01-durable-task-queue-source-implementation-r7",
    )

    def test_none_of_the_observed_tokens_is_reported(self):
        for token in self.OBSERVED:
            with self.subTest(token=token[:48]):
                findings = scanner.scan_text(token)
                self.assertEqual(
                    [f.rule_id for f in findings],
                    [],
                    f"{token[:48]} is an identifier or path, not a secret",
                )

    def test_real_token_shapes_are_still_reported(self):
        """The exemption must not be wide enough to cover a credential."""
        for token in (
            "npm_" + "aB3xQ9zLmP2kR7tW4yU6nH1jF8dS5gV0cX7e",
            "glpat-" + "xK9mQ2vR7tL4wP8nB3zY",
            "sk_" + "live_51HxQ9mN2kR7tW4yU6nH1jF8dS5gV",
            "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hL3oR6uX9bD2fG5iJ8",
        ):
            with self.subTest(token=token):
                self.assertTrue(scanner.scan_text(token))

    def test_entropy_alone_cannot_separate_the_two_sets(self):
        """Why the exemption is structural: the ranges overlap.

        A path outscores a real GitLab token, so no threshold works.
        """
        path_entropy = scanner.shannon_entropy(
            "1/AppData/Local/Temp/context-import-mutations-SYklUF/evidence"
            "/2026-09-06T02-18-07-818Z-5bb"
        )
        token_entropy = scanner.shannon_entropy("glpat-" + "xK9mQ2vR7tL4wP8nB3zY")
        self.assertGreater(path_entropy, token_entropy)

    def test_path_rule_needs_two_separators(self):
        self.assertTrue(scanner._looks_like_identifier("a/b/c"))
        self.assertFalse(scanner._looks_like_identifier("wJalrXUtnFEMI/K7MDENGb"))

    def test_base64_is_not_mistaken_for_a_word_segment(self):
        self.assertFalse(scanner._is_word_segment("aGVsbG8"))
        self.assertTrue(scanner._is_word_segment("helloWorld"))
        self.assertTrue(scanner._is_word_segment("ESMLoader"))


class RootValidationTests(unittest.TestCase):
    """Zero findings over a path that was never read is a false clean."""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.secret_file = os.path.join(self.root, "creds.env")
        with open(self.secret_file, "w", encoding="utf-8") as handle:
            handle.write(f"GITHUB_TOKEN={FAKE_GITHUB_PAT}\n")

    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = scanner.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_missing_path_is_an_error_not_a_clean_scan(self):
        stats = scanner.ScanStats()
        findings = scanner.scan_path(os.path.join(self.root, "absent"), stats=stats)
        self.assertEqual(findings, [])
        self.assertEqual(len(stats.errors), 1)
        self.assertTrue(stats.incomplete)

    def test_missing_path_exits_nonzero(self):
        code, _, err = self._run([os.path.join(self.root, "absent")])
        self.assertEqual(code, 2)
        self.assertIn("No such file", err)
        self.assertIn("scan incomplete", err)

    def test_a_real_clean_scan_exits_zero_and_is_complete(self):
        clean = os.path.join(self.root, "clean")
        os.mkdir(clean)
        with open(os.path.join(clean, "a.py"), "w", encoding="utf-8") as handle:
            handle.write("x = 1\n")
        code, _, err = self._run([clean])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")

    def test_findings_still_exit_one(self):
        code, _, err = self._run([self.secret_file])
        self.assertEqual(code, 1)
        self.assertEqual(err, "")

    def test_an_error_outranks_findings(self):
        """A partial scan must not be reported as a mere findings run."""
        code, _, err = self._run([self.secret_file, os.path.join(self.root, "absent")])
        self.assertEqual(code, 2)
        self.assertIn("scan incomplete", err)

    def test_validate_root_names_the_problem(self):
        self.assertIsNone(scanner.validate_root(self.root))
        self.assertIsNone(scanner.validate_root(self.secret_file))
        self.assertIn(
            "No such file", scanner.validate_root(os.path.join(self.root, "absent"))
        )

    def test_a_device_or_fifo_root_is_refused(self):
        fifo = os.path.join(self.root, "pipe")
        try:
            os.mkfifo(fifo)
        except (OSError, AttributeError) as error:  # pragma: no cover - platform
            self.skipTest(f"mkfifo unavailable: {error}")
        self.assertEqual(
            scanner.validate_root(fifo), "not a regular file or directory"
        )
        stats = scanner.ScanStats()
        self.assertEqual(scanner.scan_path(fifo, stats=stats), [])
        self.assertTrue(stats.errors)

    def test_unreadable_file_is_recorded_not_silently_skipped(self):
        locked = os.path.join(self.root, "locked.env")
        with open(locked, "w", encoding="utf-8") as handle:
            handle.write(f"API_TOKEN={FAKE_GITHUB_PAT}\n")
        os.chmod(locked, 0o000)
        self.addCleanup(os.chmod, locked, 0o600)
        if os.access(locked, os.R_OK):  # pragma: no cover - running as root
            self.skipTest("file is readable anyway; not running as an ordinary user")
        stats = scanner.ScanStats()
        self.assertEqual(scanner.scan_file(locked, stats=stats), [])
        self.assertEqual(stats.skipped_unreadable, 1)
        self.assertTrue(stats.incomplete)

    def test_oversize_file_is_recorded(self):
        big = os.path.join(self.root, "big.txt")
        with open(big, "w", encoding="utf-8") as handle:
            handle.write("a" * 2048)
        config = scanner.ScanConfig(max_file_bytes=1024)
        stats = scanner.ScanStats()
        self.assertEqual(scanner.scan_file(big, config, stats), [])
        self.assertEqual(stats.skipped_oversize, 1)
        self.assertTrue(stats.incomplete)

    def test_binary_skip_does_not_make_a_scan_incomplete(self):
        blob = os.path.join(self.root, "image.bin")
        with open(blob, "wb") as handle:
            handle.write(b"\x00\x01\x02" * 100)
        stats = scanner.ScanStats()
        self.assertEqual(scanner.scan_file(blob, stats=stats), [])
        self.assertEqual(stats.skipped_binary, 1)
        self.assertFalse(stats.incomplete)

    def test_summary_names_every_counter(self):
        stats = scanner.ScanStats()
        scanner.scan_path(self.root, stats=stats)
        summary = stats.summary()
        for word in ("scanned", "suppressed", "unreadable", "oversize", "binary"):
            self.assertIn(word, summary)


class SymlinkRootTests(unittest.TestCase):
    """follow_symlinks=False must hold for the root, not only for members."""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.real = os.path.join(self.root, "real")
        os.mkdir(self.real)
        with open(os.path.join(self.real, "creds.env"), "w", encoding="utf-8") as fh:
            fh.write(f"GITHUB_TOKEN={FAKE_GITHUB_PAT}\n")
        self.link = os.path.join(self.root, "link")
        os.symlink(self.real, self.link)

    def test_directory_symlink_root_is_refused_by_default(self):
        stats = scanner.ScanStats()
        findings = scanner.scan_path(self.link, stats=stats)
        self.assertEqual(findings, [])
        self.assertEqual(len(stats.errors), 1)
        self.assertIn("symlinked root", stats.errors[0])

    def test_the_refusal_is_visible_as_a_nonzero_exit(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = scanner.main([self.link])
        self.assertEqual(code, 2)
        self.assertIn("symlinked root", err.getvalue())

    def test_the_real_directory_still_scans(self):
        findings = scanner.scan_path(self.real)
        self.assertTrue(findings)

    def test_follow_symlinks_opts_back_in(self):
        config = scanner.ScanConfig(follow_symlinks=True)
        stats = scanner.ScanStats()
        findings = scanner.scan_path(self.link, config, stats)
        self.assertTrue(findings)
        self.assertEqual(stats.errors, [])

    def test_file_symlink_root_is_also_refused(self):
        target = os.path.join(self.real, "creds.env")
        link = os.path.join(self.root, "creds-link.env")
        os.symlink(target, link)
        stats = scanner.ScanStats()
        self.assertEqual(scanner.scan_path(link, stats=stats), [])
        self.assertIn("symlinked root", stats.errors[0])

    def test_a_dangling_link_root_reads_as_a_link_not_as_missing(self):
        dangling = os.path.join(self.root, "dangling")
        os.symlink(os.path.join(self.root, "nothing-here"), dangling)
        self.assertIn("symlinked root", scanner.validate_root(dangling))

    def test_a_symlinked_directory_inside_the_tree_is_not_descended(self):
        outside = os.path.join(self.root, "outside")
        os.mkdir(outside)
        with open(os.path.join(outside, "other.env"), "w", encoding="utf-8") as fh:
            fh.write(f"SLACK_TOKEN={FAKE_SLACK}\n")
        os.symlink(outside, os.path.join(self.real, "shortcut"))
        findings = scanner.scan_path(self.real)
        self.assertEqual(
            [f for f in findings if f.rule_id == "slack_token"],
            [],
            "a symlinked subdirectory was traversed",
        )


class CodeExpressionNotSecretTests(unittest.TestCase):
    """Verbatim lines from scanning a research repository, which reported [high] on each."""

    OBSERVED = (
        '    tokens = record.get("tokens")',
        "        tokens = _tokens(record, vocab)",
        "    tokens: list[int],",
    )

    def test_observed_false_positives_are_silent(self):
        for line in self.OBSERVED:
            with self.subTest(line=line.strip()):
                self.assertEqual(scanner.scan_text(line), [], line)

    def test_other_access_shapes_are_silent(self):
        for line in (
            '    secret = config["token"]',
            "    password = self.credentials.primary",
            "    api_key = os.environ.get('API_KEY')",
            "    token: Mapping[str, int] = {}",
            "    secret = build_secret(seed, vocab)",
        ):
            with self.subTest(line=line.strip()):
                self.assertEqual(scanner.scan_text(line), [], line)

    def test_a_literal_is_still_reported(self):
        """The discriminator is the call or access, not the key name."""
        self.assertTrue(scanner.scan_text('password = "s3cr3tValue123"'))
        self.assertTrue(scanner.scan_text("API_KEY=" + "abcdef123456"))
        self.assertTrue(
            scanner.scan_text('conn = connect(password="correct-horse-battery")')
        )

    def test_a_jwt_is_not_mistaken_for_a_dotted_expression(self):
        """Three base64url segments joined by dots match the same grammar."""
        self.assertFalse(scanner.is_code_expression(FAKE_JWT))
        self.assertIn("jwt", [f.rule_id for f in scanner.scan_text(FAKE_JWT)])

    def test_a_dotted_chain_needs_word_shaped_segments(self):
        self.assertTrue(scanner.is_code_expression("self.credentials.primary"))
        self.assertFalse(scanner.is_code_expression("eyJhbGciOi.eyJzdWIi.Zm9vYmFy"))

    def test_a_bare_identifier_is_not_a_code_expression(self):
        for value in ("abc123def456ghi789", "s3cr3tValue123", FAKE_GITHUB_PAT):
            with self.subTest(value=value):
                self.assertFalse(scanner.is_code_expression(value))


class PlaceholderValueTests(unittest.TestCase):
    def test_observed_payload_constants_are_silent(self):
        for line in (
            '        secret_byte = "SECRET-BYTE-PAYLOAD"',
            '        secret_depth = "SECRET-DEPTH-PAYLOAD"',
            '        secret_text = "SECRET-OUTSIDE-BYTES"',
        ):
            with self.subTest(line=line.strip()):
                self.assertEqual(scanner.scan_text(line), [], line)

    def test_user_pass_url_is_silent(self):
        line = '    for source in ("https://user:pass@example.com/a",):'
        self.assertEqual(scanner.scan_text(line), [])

    def test_a_real_url_credential_is_still_reported(self):
        line = 'url = "https://admin:hunter2xyz@example.com/a"'
        self.assertIn(
            "url_embedded_credential", [f.rule_id for f in scanner.scan_text(line)]
        )

    def test_the_marker_word_is_required(self):
        """All-capitals alone must not exempt: a base32 secret looks like that."""
        self.assertTrue(scanner.is_screaming_placeholder("SECRET-BYTE-PAYLOAD"))
        self.assertFalse(scanner.is_screaming_placeholder("JBSWY3DPEHPK3PXPKLMN"))
        self.assertFalse(scanner.is_screaming_placeholder(FAKE_AWS_ID))

    def test_mixed_case_is_not_a_screaming_placeholder(self):
        self.assertFalse(scanner.is_screaming_placeholder("Secret-Byte-Payload"))
        self.assertTrue(scanner.scan_text('password = "Secret1Byte2Payload3"'))

    def test_an_all_caps_secret_shape_is_still_reported(self):
        self.assertIn(
            "aws_access_key_id", [f.rule_id for f in scanner.scan_text(FAKE_AWS_ID)]
        )


class DigestNotSecretTests(unittest.TestCase):
    """491 of 592 entropy findings over one monorepo were sha512- integrity values."""

    FLAG_HEX = scanner.ScanConfig(entropy=scanner.EntropyConfig(flag_hex=True))
    SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    SHA256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

    def test_sha1_and_sha256_lengths_are_digests(self):
        for value in (self.SHA1, self.SHA256, self.SHA1.upper(), self.SHA256.upper()):
            with self.subTest(length=len(value)):
                self.assertTrue(scanner.is_digest_shaped(value))

    def test_a_digest_is_exempt_even_under_flag_hex(self):
        """Length, not the setting, is what says this names content."""
        for value in (self.SHA1, self.SHA256):
            with self.subTest(length=len(value)):
                self.assertEqual(scanner.scan_text(value, config=self.FLAG_HEX), [])

    def test_subresource_integrity_values_are_digests(self):
        for prefix in ("sha256", "sha384", "sha512"):
            value = prefix + "-aB3xQ9zLmP2kR7tW4yU6nH1jF8dS5gV0cX7eKqWnBvC="
            with self.subTest(prefix=prefix):
                self.assertTrue(scanner.is_digest_shaped(value))
                self.assertEqual(scanner.scan_text(value), [])

    def test_an_integrity_line_from_a_lockfile_is_silent(self):
        line = '      "integrity": "sha512-aB3xQ9zLmP2kR7tW4yU6nH1jF8dS5gV0cX7eKqWnBvC=",'
        self.assertEqual(scanner.scan_text(line), [])

    def test_a_non_digest_hex_length_is_still_reported(self):
        value = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822c"
        self.assertEqual(len(value), 48)
        self.assertFalse(scanner.is_digest_shaped(value))
        self.assertIn(
            "high_entropy_hex",
            [f.rule_id for f in scanner.scan_text(value, config=self.FLAG_HEX)],
        )

    def test_a_base64_token_of_digest_length_is_still_reported(self):
        value = "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hL3oR6uX9bD2fG5iJ8"
        self.assertFalse(scanner.is_digest_shaped(value))
        self.assertTrue(scanner.scan_text(value))

    def test_a_digest_assigned_to_a_secret_named_variable_is_reported(self):
        """The length exemption belongs to the entropy pass, not to every rule.

        An assignment is a different claim from a bare token: a 64-hex value
        assigned to a secret-named variable is an assigned secret, and the
        earlier version of this test asserted the opposite.
        """
        self.assertIn(
            "dotenv_secret",
            [f.rule_id for f in scanner.scan_text(f"EXPECTED_TOKEN_SHA256={self.SHA256}")],
        )

    def test_a_real_secret_assigned_the_same_way_is_reported(self):
        self.assertTrue(scanner.scan_text(f"EXPECTED_TOKEN={FAKE_GITHUB_PAT}"))


class TokenBoundaryTests(unittest.TestCase):
    """``=`` is base64 padding and only ever trails."""

    def test_an_assignment_is_not_one_token(self):
        line = '    return format(value.quantize(_SIX, rounding=ROUND_HALF_EVEN), "f")'
        self.assertEqual(scanner.scan_text(line), [])

    def test_padding_is_still_part_of_a_base64_token(self):
        value = "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hL3oR6uX9bD2fG5i=="
        findings = scanner.scan_text(value)
        self.assertTrue(findings)
        self.assertIn("48", findings[0].redacted)

    def test_an_interior_equals_splits_the_token(self):
        # Both sides are 16+ characters, so each would be a token on its own;
        # the point is that the "=" does not join them into one.
        text = "averylongleftsidename=ANOTHERVERYLONGRIGHTSIDE"
        self.assertEqual(
            [m.group(0) for m in scanner._TOKEN_RE.finditer(text)],
            ["averylongleftsidename=", "ANOTHERVERYLONGRIGHTSIDE"],
        )

    def test_the_observed_line_yields_no_token_at_all(self):
        """Both halves are under the 16-character floor once "=" cannot join."""
        self.assertEqual(
            [m.group(0) for m in scanner._TOKEN_RE.finditer("rounding=ROUND_HALF_EVEN")],
            [],
        )


class CapturePositionTests(unittest.TestCase):
    """Found in review: an exemption is only safe in the right position.

    The earlier version applied digest, placeholder, call and dotted-chain
    shapes to every capture of every rule, which dropped real secrets. Each
    case below is verbatim from that review.
    """

    SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    SHA256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

    def _ids(self, text):
        return [f.rule_id for f in scanner.scan_text(text)]

    # 1: hex length is an entropy signal, not a rule-wide exemption.
    def test_hex_assigned_in_dotenv_form_reports(self):
        self.assertIn("dotenv_secret", self._ids(f"API_KEY={self.SHA256}"))
        self.assertIn("dotenv_secret", self._ids(f"CLIENT_SECRET={self.SHA1}"))

    def test_hex_as_a_bearer_token_reports(self):
        self.assertIn("bearer_token", self._ids(f"Authorization: Bearer {self.SHA256}"))

    def test_hex_as_a_url_password_reports(self):
        self.assertIn(
            "url_embedded_credential",
            self._ids(f"https://admin:{self.SHA256}@example.com"),
        )

    def test_a_bare_hex_digest_is_still_exempt_in_the_entropy_pass(self):
        config = scanner.ScanConfig(entropy=scanner.EntropyConfig(flag_hex=True))
        self.assertEqual(scanner.scan_text(self.SHA256, config=config), [])
        self.assertEqual(scanner.scan_text(self.SHA1, config=config), [])

    # 2: the integrity shape is entropy-only too.
    def test_an_integrity_shaped_password_reports(self):
        text = 'password = "sha256-aB3xQ9zLmP2kR7tW4yU6nH1jF8dS5gV0cX7eKqWnBvC="'
        self.assertIn("password_assignment", self._ids(text))

    def test_a_bare_integrity_value_is_still_exempt(self):
        self.assertEqual(
            scanner.scan_text("sha512-aB3xQ9zLmP2kR7tW4yU6nH1jF8dS5gV0cX7eKqWnBvC="), []
        )

    # 3: a placeholder marker must be a whole segment.
    def test_a_marker_inside_a_word_does_not_exempt(self):
        self.assertFalse(scanner.is_screaming_placeholder("SUPERSECRETVALUE123"))
        self.assertIn("password_assignment", self._ids('password = "SUPERSECRETVALUE123"'))

    def test_an_aws_id_containing_a_marker_reports(self):
        self.assertIn("aws_access_key_id", self._ids("AKIA" + "TESTQQQQQQQQQQQQ"))

    def test_a_url_password_with_a_marker_segment_reports(self):
        self.assertIn(
            "url_embedded_credential",
            self._ids("https://admin:TEST-ADMIN-TOKEN@example.com"),
        )

    def test_a_whole_segment_marker_still_exempts(self):
        self.assertTrue(scanner.is_screaming_placeholder("SECRET-BYTE-PAYLOAD"))
        self.assertEqual(scanner.scan_text('x = "SECRET-BYTE-PAYLOAD"'), [])

    # 4: a call or subscript inside a string literal is not source code.
    def test_a_call_shaped_string_literal_reports(self):
        self.assertIn("password_assignment", self._ids('password = "lookup(seedvalue123)"'))

    def test_a_subscript_shaped_string_literal_reports(self):
        self.assertIn("password_assignment", self._ids('password = "data[abcdefghij]"'))

    def test_a_token_inside_a_call_is_still_scanned(self):
        text = f'secret = call("{FAKE_GITHUB_PAT}")'
        self.assertIn("github_pat", self._ids(text))

    def test_an_unquoted_call_is_still_exempt(self):
        self.assertEqual(scanner.scan_text('    tokens = record.get("tokens")'), [])

    # 5: a dotted chain is only an access path where code can appear.
    def test_a_dotted_url_password_reports(self):
        self.assertIn(
            "url_embedded_credential",
            self._ids("https://admin:Correct.Horse.Battery@example.com"),
        )

    def test_a_dotted_string_literal_reports(self):
        text = 'password = "Abcdefghij.Klmnopqrst.Uvwxyzabcd"'
        self.assertIn("password_assignment", self._ids(text))

    def test_an_unquoted_dotted_access_is_still_exempt(self):
        self.assertEqual(
            scanner.scan_text("    password = self.credentials.primary"), []
        )

    def test_a_jwt_still_reports(self):
        self.assertIn("jwt", self._ids(FAKE_JWT))

    # The five shapes the review listed as still working must keep working.
    def test_the_shapes_that_already_worked_still_report(self):
        for text in (
            f'secret = call("{FAKE_GITHUB_PAT}")',
            f'token: list[int] = "{FAKE_GITHUB_PAT}"',
            f'api_key: str = "{FAKE_GITHUB_PAT}"',
            "-----BEGIN RSA " + "PRIVATE KEY-----",
            "https://admin:hunter2xyz@example.com",
        ):
            with self.subTest(text=text[:44]):
                self.assertTrue(scanner.scan_text(text), text)

    def test_the_exact_placeholder_pair_stays_silent(self):
        self.assertEqual(scanner.scan_text("https://user:pass@example.com"), [])

    def test_position_flags_are_honoured_directly(self):
        value = "Correct.Horse.Battery"
        self.assertTrue(
            scanner.is_benign_value(value, quoted=False, credential_position=False)
        )
        self.assertFalse(
            scanner.is_benign_value(value, quoted=True, credential_position=False)
        )
        self.assertFalse(
            scanner.is_benign_value(value, quoted=False, credential_position=True)
        )


class PublicHashShapeTests(unittest.TestCase):
    """Shapes reported from a static website project as false positives.

    All four were already silent when the note arrived; these tests pin that,
    because the exemption lives in the entropy pass and a future change to
    where it is applied would bring them all back at once.
    """

    OBSERVED = (
        '      "integrity": "sha512-aB3xQ9zLmP2kR7tW4yU6nH1jF8dS5gV0cX7eKqWnBvCdEfGhIjKlMnOpQrStUvWxYz==",',
        '<script src="/a.js" integrity="sha384-aB3xQ9zLmP2kR7tW4yU6nH1jF8dS5gV0cX7eKqWnBvCdEfGhIjKl" crossorigin></script>',
        "script-src 'self' 'sha256-aB3xQ9zLmP2kR7tW4yU6nH1jF8dS5gV0cX7eKqWnBvC=' 'unsafe-inline';",
        '<script type="application/ld+json">{"@context":"https://schema.org","@type":"Person",'
        '"sameAs":["https://www.linkedin.com/in/aliceexample"]}</script>',
    )

    def test_public_hash_shapes_are_silent(self):
        for line in self.OBSERVED:
            with self.subTest(line=line[:52]):
                self.assertEqual(scanner.scan_text(line), [], line)

    def test_each_integrity_prefix_is_recognised(self):
        for prefix in ("sha256", "sha384", "sha512"):
            value = prefix + "-aB3xQ9zLmP2kR7tW4yU6nH1jF8dS5gV0cX7eKqWnBvC="
            with self.subTest(prefix=prefix):
                self.assertTrue(scanner.is_digest_shaped(value))

    def test_a_real_secret_beside_an_integrity_value_still_reports(self):
        """The exemption is per token, not per line."""
        line = f'{{"integrity": "sha512-aB3xQ9zLmP2kR7tW4yU6nH1jF8=", "token": "{FAKE_GITHUB_PAT}"}}'
        self.assertIn("github_pat", [f.rule_id for f in scanner.scan_text(line)])

    def test_an_integrity_shaped_assignment_still_reports(self):
        """Position still decides: entropy-only means the assignment rules see it."""
        text = 'password = "sha256-aB3xQ9zLmP2kR7tW4yU6nH1jF8dS5gV0cX7eKqWnBvC="'
        self.assertTrue(scanner.scan_text(text))


class SkippedDirectoryTests(unittest.TestCase):
    """A skipped directory is a policy choice, but it has to be named.

    Built output is where an environment value gets baked into a bundle, so
    reporting nothing over an unwalked dist/ reads exactly like coverage.
    """

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        os.mkdir(os.path.join(self.root, "dist"))
        with open(os.path.join(self.root, "dist", "bundle.js"), "w", encoding="utf-8") as handle:
            handle.write(f'const t = "{FAKE_GITHUB_PAT}";\n')
        with open(os.path.join(self.root, "src.js"), "w", encoding="utf-8") as handle:
            handle.write("const x = 1;\n")

    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = scanner.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_build_output_is_skipped_by_default(self):
        stats = scanner.ScanStats()
        findings = scanner.scan_path(self.root, stats=stats)
        self.assertEqual(findings, [])
        self.assertEqual(stats.skipped_dirs, {"dist": 1})

    def test_the_skip_is_named_in_the_summary(self):
        stats = scanner.ScanStats()
        scanner.scan_path(self.root, stats=stats)
        summary = stats.summary()
        self.assertIn("1 director(ies) not walked", summary)
        self.assertIn("dist", summary)

    def test_a_skipped_directory_does_not_make_a_scan_incomplete(self):
        """Not reading something by policy is different from failing to read it."""
        stats = scanner.ScanStats()
        scanner.scan_path(self.root, stats=stats)
        self.assertFalse(stats.incomplete)
        self.assertEqual(stats.errors, [])

    def test_the_cli_names_the_skip_and_still_exits_zero(self):
        code, out, _ = self._run([self.root])
        self.assertEqual(code, 0)
        self.assertIn("dist", out)
        self.assertIn("not walked", out)

    def test_scan_build_output_finds_the_baked_in_secret(self):
        code, out, _ = self._run(["--scan-build-output", self.root])
        self.assertEqual(code, 1)
        self.assertIn("github_pat", out)
        self.assertNotIn(FAKE_GITHUB_PAT, out)

    def test_the_flag_only_reinstates_build_output(self):
        self.assertEqual(scanner.BUILD_OUTPUT_DIRS, frozenset({"dist", "build"}))
        remaining = scanner.DEFAULT_SKIP_DIRS - scanner.BUILD_OUTPUT_DIRS
        for name in (".git", "node_modules", "__pycache__", ".venv"):
            self.assertIn(name, remaining)

    def test_repeated_skips_are_counted(self):
        os.mkdir(os.path.join(self.root, "pkg"))
        os.mkdir(os.path.join(self.root, "pkg", "dist"))
        stats = scanner.ScanStats()
        scanner.scan_path(self.root, stats=stats)
        self.assertEqual(stats.skipped_dirs["dist"], 2)
        self.assertIn("distx2", stats.summary())


class CredentialLocatorTests(unittest.TestCase):
    """A locator names where a secret lives; it is not the secret.

    Found by a provider conformance suite: a conforming provider
    profile carrying `"credential_ref": "env:ANTHROPIC_API_KEY"` was reported
    as `mapping_secret`, because the key contains "credential" and the value is
    neither a placeholder nor a code expression.
    """

    def _ids(self, text):
        return [f.rule_id for f in scanner.scan_text(text)]

    def test_the_observed_profile_line_is_silent(self):
        line = '  "credential_ref": "env:ANTHROPIC_API_KEY"'
        self.assertEqual(scanner.scan_text(line), [], line)

    def test_each_locator_scheme_is_recognised(self):
        for value in (
            "env:ANTHROPIC_API_KEY",
            "file:/run/secrets/git_deploy_key",
            "keyring:myservice/claude",
            "vault:kv/myservice/app",
            "secretref:provider.local",
        ):
            with self.subTest(value=value):
                self.assertTrue(scanner.is_credential_locator(value))
                self.assertEqual(scanner.scan_text(f'  "credential": "{value}"'), [])

    def test_the_prefix_is_not_an_escape_hatch(self):
        """A locator whose target is itself secret-shaped is still a finding."""
        for token in (FAKE_GITHUB_PAT, FAKE_AWS_ID, "npm_" + "a" * 36):
            with self.subTest(token=token[:10]):
                self.assertFalse(scanner.is_credential_locator(f"env:{token}"))
                self.assertTrue(scanner.scan_text(f'  "credential_ref": "env:{token}"'))

    def test_a_bare_token_in_that_field_still_reports(self):
        line = f'  "credential_ref": "{FAKE_GITHUB_PAT}"'
        self.assertIn("github_pat", self._ids(line))

    def test_an_unknown_scheme_is_not_a_locator(self):
        for value in ("https://example.com/key", "secret:" + "abc123def456", "env", "env:"):
            with self.subTest(value=value):
                self.assertFalse(scanner.is_credential_locator(value))

    def test_a_locator_shape_does_not_excuse_a_real_secret_elsewhere(self):
        line = f'{{"credential_ref": "env:A", "token": "{FAKE_GITHUB_PAT}"}}'
        self.assertIn("github_pat", self._ids(line))

    def test_a_password_assignment_of_a_locator_is_silent(self):
        self.assertEqual(scanner.scan_text('password = "env:DB_PASSWORD"'), [])

    # Found in review: the body was checked only against the named
    # rules, not against the entropy pass, so a locator prefix in front of a
    # random value was benign in both paths.
    @staticmethod
    def _synthetic_body(seed, length):
        """A high-entropy body built at runtime, so no token shape is committed."""
        raw = base64.urlsafe_b64encode(hashlib.sha256(seed.encode()).digest())
        return raw.decode().rstrip("=")[:length]

    def test_a_high_entropy_body_is_not_a_locator(self):
        for scheme in ("env", "file", "keyring", "vault", "secretref"):
            for length in (24, 32, 40, 43):
                body = self._synthetic_body(f"{scheme}-{length}", length)
                value = f"{scheme}:{body}"
                with self.subTest(scheme=scheme, length=length):
                    self.assertFalse(scanner.is_credential_locator(value))
                    self.assertTrue(scanner.scan_text(f'  "credential_ref": "{value}"'))

    def test_the_hidden_body_is_reported_in_an_api_key_field_too(self):
        body = self._synthetic_body("api-key-field", 40)
        self.assertTrue(scanner.scan_text(f'  "api_key": "vault:{body}"'))

    def test_a_finding_on_a_hidden_body_still_carries_no_secret(self):
        body = self._synthetic_body("redaction", 40)
        out = "\n".join(
            f.redacted for f in scanner.scan_text(f'  "credential_ref": "vault:{body}"')
        )
        self.assertNotIn(body, out)

    def test_a_short_dense_body_is_refused_by_shape(self):
        """Entropy per character is capped at log2(len), so the short range needs shape."""
        for length in (12, 16, 20):
            body = self._synthetic_body(f"short-{length}", length)
            # Only exercises the rule when the synthetic value really is dense.
            if not (any(c.islower() for c in body) and any(c.isupper() for c in body)
                    and any(c.isdigit() for c in body)):
                continue
            with self.subTest(length=length):
                self.assertFalse(scanner.is_credential_locator(f"vault:{body}"))

    def test_real_locator_bodies_are_still_benign(self):
        """The negative controls: the fix must not re-break the case it was built for."""
        for value in (
            "env:ANTHROPIC_API_KEY",
            "env:XAI_TOKEN_2026",
            "file:/var/lib/myservice/providers/local-llama/key",
            "keyring:myservice/grok",
            "keyring:myservice/myService",
            "keyring:providers/Qwen3-8B-Instruct",
            "vault:kv/myservice/app",
            "vault:s3/eu-west-1/myservice-prod/key",
            "secretref:provider.local",
            "file:models/llama3.1-70b/key",
        ):
            with self.subTest(value=value):
                self.assertTrue(scanner.is_credential_locator(value))
                self.assertEqual(scanner.scan_text(f'  "credential_ref": "{value}"'), [])

    def test_a_long_camel_case_name_is_a_known_false_positive(self):
        """The cost of the shape test, pinned rather than left to be discovered.

        A single real name of 16+ characters mixing cases is refused. In a
        credential field a review is cheap; this test exists so the trade is
        visible and a later change to it is deliberate.
        """
        self.assertFalse(scanner.is_credential_locator("keyring:aliceexampleDotCom"))
        # The same name under 16 characters, and the same length in one case
        # class, both stay benign: length alone and case alone are not the rule.
        self.assertTrue(scanner.is_credential_locator("keyring:aliceDotCom"))
        self.assertTrue(scanner.is_credential_locator("keyring:aliceexampledotcom"))

    def test_a_blob_split_by_separators_is_still_opaque(self):
        """Why the rejoin rule exists: base64url carries - and _, so the per-word
        tests see a long blob in short pieces."""
        body = self._synthetic_body("separated", 40)
        self.assertFalse(scanner.is_credential_locator(f"vault:{body}"))
        # Built to be seen only by the rejoin rule: every word is short.
        pieces = [body[i:i + 6] for i in range(0, 30, 6)]
        self.assertFalse(scanner.is_credential_locator("vault:" + "-".join(pieces)))

    def test_a_real_path_is_not_opaque_when_rejoined(self):
        """The negative control for the rejoin rule: separators are not entropy."""
        for value in ("file:/run/secrets/git_deploy_key",
                      "env:OPENAI_API_KEY_PRODUCTION",
                      "keyring:providers/Qwen3-8B-Instruct",
                      "file:/var/lib/myservice/providers/local-llama/key"):
            with self.subTest(value=value):
                self.assertTrue(scanner.is_credential_locator(value))

    def test_a_body_outside_its_scheme_shape_is_not_a_locator(self):
        for value in ("env:lower_case_name", "env:MIXED_Case", "file://double//slash",
                      "keyring:/", "vault:a//b"):
            with self.subTest(value=value):
                self.assertFalse(scanner.is_credential_locator(value))


if __name__ == "__main__":
    unittest.main()
