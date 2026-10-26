# PROVENANCE (mirror of .provenance/ledger.jsonl; ledger wins)
# written-by: unknown (pre-provenance) | 2026-10-09 | f032f17
# modified-by: codex/gpt-5.6-sol | 2026-10-26 | 1aaa682 | cover forbidden default ACL principals and add provenance block
# reviewed-by: claude-code/claude-opus-5-5 | 2026-10-26 | APPROVE_WITH_NITS
# END PROVENANCE
"""Tests for guardlib.permcheck.

ACL rules are exercised two ways: against fixture text (so every rule is
covered on any host) and against real ACLs built with setfacl in a temp dir
(so the parser is checked against what libacl actually prints). Nothing
requires root; the integration tests skip when setfacl cannot create the
entry under test.
"""

import contextlib
import io
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from guardlib import permcheck  # noqa: E402


def _setfacl(*args) -> bool:
    """Run setfacl, returning False when it is unavailable or refuses."""
    binary = shutil.which("setfacl")
    if binary is None:
        return False
    result = subprocess.run(
        [binary, *args], capture_output=True, text=True, check=False
    )
    return result.returncode == 0


class PermBitTests(unittest.TestCase):
    def test_round_trip(self):
        for perms in ("rwx", "r--", "-w-", "--x", "---", "rw-", "r-x"):
            with self.subTest(perms=perms):
                bits = permcheck.perms_to_bits(perms)
                self.assertEqual(permcheck.bits_to_perms(bits), perms)

    def test_capital_x_counts_as_execute(self):
        self.assertEqual(permcheck.perms_to_bits("r-X"), permcheck.READ | permcheck.EXEC)

    def test_sticky_and_setid_chars_count_as_execute(self):
        self.assertTrue(permcheck.perms_to_bits("rwt") & permcheck.EXEC)
        self.assertTrue(permcheck.perms_to_bits("rws") & permcheck.EXEC)

    def test_short_and_empty_strings_do_not_raise(self):
        self.assertEqual(permcheck.perms_to_bits(""), 0)
        self.assertEqual(permcheck.perms_to_bits("r"), permcheck.READ)


class ParseTests(unittest.TestCase):
    SIMPLE = "user::rw-\ngroup::r--\nother::r--\n"

    NAMED = (
        "user::rwx\n"
        "user:agent-bot:r-x\t#effective:---\n"
        "user:4294967295:r-x\t#effective:---\n"
        "group::r-x\t#effective:---\n"
        "mask::---\n"
        "other::---\n"
    )

    WITH_DEFAULT = (
        "user::rwx\n"
        "user:agent-bot:r-x\n"
        "group::r-x\n"
        "mask::r-x\n"
        "other::---\n"
        "default:user::rwx\n"
        "default:user:agent-bot:r-x\n"
        "default:group::r-x\n"
        "default:mask::r-x\n"
        "default:other::---\n"
    )

    def test_simple_acl_has_three_base_entries(self):
        acl = permcheck.parse_getfacl(self.SIMPLE)
        self.assertEqual(len(acl.entries), 3)
        self.assertIsNone(acl.mask)
        self.assertEqual(acl.named(), [])

    def test_comment_header_is_ignored(self):
        text = "# file: some/path\n# owner: root\n# group: root\n" + self.SIMPLE
        acl = permcheck.parse_getfacl(text)
        self.assertEqual(len(acl.entries), 3)

    def test_named_entries_are_collected(self):
        acl = permcheck.parse_getfacl(self.NAMED)
        named = acl.named("user")
        self.assertEqual(len(named), 2)
        self.assertEqual(
            {e.qualifier for e in named}, {"agent-bot", "4294967295"}
        )

    def test_effective_comment_is_stripped_not_trusted(self):
        acl = permcheck.parse_getfacl(self.NAMED)
        entry = acl.find_named("user", "agent-bot")
        # The declared value survives parsing; the comment does not leak into it.
        self.assertEqual(entry.perms, "r-x")

    def test_mask_is_exposed(self):
        acl = permcheck.parse_getfacl(self.NAMED)
        self.assertIsNotNone(acl.mask)
        self.assertEqual(acl.mask.perms, "---")

    def test_unresolved_qualifier_is_flagged(self):
        acl = permcheck.parse_getfacl(self.NAMED)
        entry = acl.find_named("user", "4294967295")
        self.assertTrue(entry.is_unresolved)
        self.assertFalse(acl.find_named("user", "agent-bot").is_unresolved)

    def test_default_entries_are_separated(self):
        acl = permcheck.parse_getfacl(self.WITH_DEFAULT)
        self.assertTrue(acl.has_default)
        self.assertEqual(len(acl.default_entries), 5)
        self.assertEqual(acl.default_mask.perms, "r-x")
        # Default entries must not pollute the access list.
        self.assertEqual(len(acl.entries), 5)

    def test_no_default_acl_reports_false(self):
        self.assertFalse(permcheck.parse_getfacl(self.SIMPLE).has_default)

    def test_malformed_lines_are_skipped(self):
        text = "garbage\nuser::rw-\nuser:bad\nnot:a:perm\nother::r--\n"
        acl = permcheck.parse_getfacl(text)
        kinds = [(e.kind, e.qualifier) for e in acl.entries]
        self.assertIn(("user", None), kinds)
        self.assertIn(("other", None), kinds)
        self.assertEqual(len(acl.entries), 2)

    def test_empty_input_yields_empty_acl(self):
        acl = permcheck.parse_getfacl("")
        self.assertEqual(acl.entries, [])
        self.assertTrue(acl.available)

    def test_entry_label_round_trips(self):
        acl = permcheck.parse_getfacl(self.WITH_DEFAULT)
        self.assertEqual(
            acl.find_named("user", "agent-bot").label(), "user:agent-bot:r-x"
        )
        default_named = [e for e in acl.default_entries if e.is_named][0]
        self.assertEqual(default_named.label(), "default:user:agent-bot:r-x")


class MaskClippingTests(unittest.TestCase):
    """POSIX 1003.1e: the mask clips named entries and the owning group only."""

    def setUp(self):
        self.acl = permcheck.parse_getfacl(ParseTests.NAMED)

    def test_named_user_is_clipped_to_nothing(self):
        entry = self.acl.find_named("user", "agent-bot")
        self.assertEqual(entry.perms, "r-x")
        self.assertEqual(permcheck.effective_perms(entry, self.acl.mask), "---")

    def test_owning_group_is_clipped(self):
        group = [e for e in self.acl.entries if e.kind == "group" and not e.is_named][0]
        self.assertTrue(permcheck.mask_applies_to(group))
        self.assertEqual(permcheck.effective_perms(group, self.acl.mask), "---")

    def test_owner_entry_is_not_clipped(self):
        owner = [e for e in self.acl.entries if e.kind == "user" and not e.is_named][0]
        self.assertFalse(permcheck.mask_applies_to(owner))
        self.assertEqual(permcheck.effective_perms(owner, self.acl.mask), "rwx")

    def test_other_entry_is_not_clipped(self):
        text = "user::rwx\nuser:agent-bot:rwx\ngroup::rwx\nmask::---\nother::r--\n"
        acl = permcheck.parse_getfacl(text)
        other = [e for e in acl.entries if e.kind == "other"][0]
        self.assertFalse(permcheck.mask_applies_to(other))
        self.assertEqual(permcheck.effective_perms(other, acl.mask), "r--")

    def test_mask_entry_itself_is_not_clipped(self):
        self.assertFalse(permcheck.mask_applies_to(self.acl.mask))

    def test_partial_mask_clips_only_missing_bits(self):
        text = "user::rwx\nuser:dev:rwx\ngroup::rwx\nmask::r-x\nother::---\n"
        acl = permcheck.parse_getfacl(text)
        entry = acl.find_named("user", "dev")
        self.assertEqual(permcheck.effective_perms(entry, acl.mask), "r-x")

    def test_absent_mask_means_no_clipping(self):
        text = "user::rwx\nuser:dev:rwx\ngroup::rwx\nother::---\n"
        acl = permcheck.parse_getfacl(text)
        entry = acl.find_named("user", "dev")
        self.assertEqual(permcheck.effective_perms(entry, acl.mask), "rwx")

    def test_effective_for_helper_matches(self):
        self.assertEqual(self.acl.effective_for("user", "agent-bot"), "---")
        self.assertIsNone(self.acl.effective_for("user", "absent"))


class CollectTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="guard-perm-")
        self.root = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def _file(self, name="f", mode=0o600):
        path = os.path.join(self.root, name)
        with open(path, "w") as handle:
            handle.write("x")
        os.chmod(path, mode)
        return path

    def test_missing_path_reports_not_exists(self):
        facts = permcheck.collect(os.path.join(self.root, "nope"))
        self.assertFalse(facts.exists)

    def test_mode_is_captured(self):
        facts = permcheck.collect(self._file(mode=0o640))
        self.assertEqual(facts.mode, 0o640)
        self.assertEqual(facts.mode_octal, "0640")

    def test_owner_and_group_resolve_to_names(self):
        facts = permcheck.collect(self._file())
        self.assertEqual(facts.uid, os.getuid())
        self.assertIsNotNone(facts.owner)

    def test_directory_is_detected(self):
        facts = permcheck.collect(self.root)
        self.assertTrue(facts.is_dir)

    def test_symlink_is_detected_and_acl_is_skipped(self):
        target = self._file("target")
        link = os.path.join(self.root, "link")
        os.symlink(target, link)
        facts = permcheck.collect(link)
        self.assertTrue(facts.is_symlink)
        self.assertFalse(facts.acl.available)

    def test_world_bits(self):
        facts = permcheck.collect(self._file(mode=0o644))
        self.assertTrue(facts.world_readable)
        self.assertFalse(facts.world_writable)
        facts = permcheck.collect(self._file("ww", mode=0o666))
        self.assertTrue(facts.world_writable)

    def test_group_bits(self):
        facts = permcheck.collect(self._file(mode=0o660))
        self.assertTrue(facts.group_readable)
        self.assertTrue(facts.group_writable)

    def test_special_bits(self):
        path = self._file("sticky", mode=0o600)
        os.chmod(path, 0o600 | stat.S_ISVTX)
        self.assertTrue(permcheck.collect(path).sticky)

    def test_acl_can_be_skipped(self):
        facts = permcheck.collect(self._file(), with_acl=False)
        self.assertFalse(facts.acl.available)

    def test_acl_is_read_when_available(self):
        facts = permcheck.collect(self._file())
        if shutil.which("getfacl") is None:
            self.skipTest("getfacl not installed")
        self.assertTrue(facts.acl.available)
        self.assertTrue(facts.acl.entries)


class VerifyTests(unittest.TestCase):
    def _facts(self, **kwargs):
        base = dict(path="/p", exists=True, mode=0o600, owner="me", group="mine")
        base.update(kwargs)
        return permcheck.PathFacts(**base)

    def _checks(self, facts, policy):
        return {f.check for f in permcheck.verify(facts, policy)}

    def test_clean_path_has_no_findings(self):
        policy = permcheck.PathPolicy(mode_exactly=0o600, owner="me", group="mine")
        self.assertEqual(permcheck.verify(self._facts(), policy), [])

    def test_missing_path_when_required(self):
        facts = permcheck.PathFacts(path="/p", exists=False)
        policy = permcheck.PathPolicy()
        self.assertEqual(self._checks(facts, policy), {"must_exist"})

    def test_missing_path_when_optional_is_clean(self):
        facts = permcheck.PathFacts(path="/p", exists=False)
        policy = permcheck.PathPolicy(must_exist=False)
        self.assertEqual(permcheck.verify(facts, policy), [])

    def test_mode_exactly_mismatch(self):
        policy = permcheck.PathPolicy(mode_exactly=0o600)
        self.assertEqual(self._checks(self._facts(mode=0o640), policy), {"mode_exactly"})

    def test_mode_at_most_allows_tighter(self):
        policy = permcheck.PathPolicy(mode_at_most=0o750)
        self.assertEqual(permcheck.verify(self._facts(mode=0o600), policy), [])

    def test_mode_at_most_rejects_looser(self):
        policy = permcheck.PathPolicy(mode_at_most=0o600)
        checks = self._checks(self._facts(mode=0o644), policy)
        self.assertIn("mode_at_most", checks)

    def test_mode_at_most_names_the_extra_bits(self):
        policy = permcheck.PathPolicy(mode_at_most=0o600)
        findings = permcheck.verify(self._facts(mode=0o640), policy)
        message = next(f.message for f in findings if f.check == "mode_at_most")
        self.assertIn("0040", message)

    def test_world_readable_is_flagged(self):
        checks = self._checks(self._facts(mode=0o644), permcheck.PathPolicy())
        self.assertIn("world_readable", checks)

    def test_world_readable_can_be_allowed(self):
        policy = permcheck.PathPolicy(allow_world_readable=True)
        self.assertNotIn("world_readable", self._checks(self._facts(mode=0o644), policy))

    def test_world_writable_is_critical(self):
        findings = permcheck.verify(self._facts(mode=0o666), permcheck.PathPolicy())
        severity = next(f.severity for f in findings if f.check == "world_writable")
        self.assertEqual(severity, "critical")

    def test_group_writable_opt_in_check(self):
        policy = permcheck.PathPolicy(allow_group_writable=False)
        self.assertIn("group_writable", self._checks(self._facts(mode=0o660), policy))

    def test_setuid_is_flagged_critical(self):
        facts = self._facts(mode=0o600 | stat.S_ISUID)
        findings = permcheck.verify(facts, permcheck.PathPolicy())
        severity = next(f.severity for f in findings if f.check == "setuid")
        self.assertEqual(severity, "critical")

    def test_owner_mismatch(self):
        policy = permcheck.PathPolicy(owner="root")
        self.assertIn("owner", self._checks(self._facts(), policy))

    def test_group_mismatch(self):
        policy = permcheck.PathPolicy(group="wheel")
        self.assertIn("group", self._checks(self._facts(), policy))

    def test_unresolved_owner_falls_back_to_uid_in_report(self):
        facts = self._facts(owner=None, uid=4242)
        findings = permcheck.verify(facts, permcheck.PathPolicy(owner="me"))
        self.assertEqual(findings[0].actual, "4242")

    def test_symlink_forbidden(self):
        facts = self._facts(is_symlink=True)
        policy = permcheck.PathPolicy(forbid_symlink=True)
        self.assertIn("forbid_symlink", self._checks(facts, policy))


class AclPolicyTests(unittest.TestCase):
    def _facts_with(self, text, **kwargs):
        base = dict(
            path="/p",
            exists=True,
            mode=0o640,
            owner="me",
            group="mine",
            acl=permcheck.parse_getfacl(text),
        )
        base.update(kwargs)
        return permcheck.PathFacts(**base)

    EFFECTIVE = (
        "user::rwx\nuser:agent-bot:r--\ngroup::r--\nmask::r--\nother::---\n"
    )
    CLIPPED = (
        "user::rwx\nuser:agent-bot:r--\ngroup::r--\nmask::---\nother::---\n"
    )

    def test_required_entry_present_and_effective_passes(self):
        policy = permcheck.PathPolicy(
            require_effective=(("user", "agent-bot", "r--"),)
        )
        self.assertEqual(permcheck.verify(self._facts_with(self.EFFECTIVE), policy), [])

    def test_required_entry_absent_is_flagged(self):
        policy = permcheck.PathPolicy(
            require_effective=(("user", "someone-else", "r--"),)
        )
        findings = permcheck.verify(self._facts_with(self.EFFECTIVE), policy)
        self.assertEqual(findings[0].check, "require_effective")
        self.assertEqual(findings[0].actual, "absent")

    def test_required_entry_clipped_by_mask_is_flagged(self):
        """The bug this module exists to catch: declared but not effective."""
        policy = permcheck.PathPolicy(
            require_effective=(("user", "agent-bot", "r--"),)
        )
        findings = permcheck.verify(self._facts_with(self.CLIPPED), policy)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].check, "require_effective")
        self.assertIn("clipped by mask", findings[0].message)
        self.assertIn("declared r--", findings[0].actual)
        self.assertIn("effective ---", findings[0].actual)

    def test_insufficient_rather_than_clipped_is_distinguished(self):
        text = "user::rwx\nuser:dev:r--\ngroup::r--\nmask::rwx\nother::---\n"
        policy = permcheck.PathPolicy(require_effective=(("user", "dev", "rw-"),))
        findings = permcheck.verify(self._facts_with(text), policy)
        self.assertIn("insufficient permissions", findings[0].message)

    def test_forbidden_entry_present_is_flagged(self):
        policy = permcheck.PathPolicy(forbid_named=(("user", "agent-bot"),))
        findings = permcheck.verify(self._facts_with(self.EFFECTIVE), policy)
        self.assertEqual(findings[0].check, "forbid_named")

    def test_forbidden_entry_flagged_even_when_inert(self):
        """An inert grant is still a grant waiting for a mask widen."""
        policy = permcheck.PathPolicy(forbid_named=(("user", "agent-bot"),))
        findings = permcheck.verify(self._facts_with(self.CLIPPED), policy)
        self.assertEqual(findings[0].check, "forbid_named")
        self.assertIn("effective ---", findings[0].actual)

    def test_forbidden_entry_in_default_acl_is_flagged(self):
        text = (
            "user::rwx\ngroup::r-x\nmask::r-x\nother::---\n"
            "default:user::rwx\ndefault:user:agent-bot:r-x\n"
            "default:group::r-x\ndefault:mask::---\ndefault:other::---\n"
        )
        policy = permcheck.PathPolicy(forbid_named=(("user", "agent-bot"),))
        findings = permcheck.verify(self._facts_with(text, is_dir=True), policy)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].check, "forbid_named")
        self.assertIn("default ACL", findings[0].message)
        self.assertIn("effective ---", findings[0].actual)

    def test_mask_exactly_match_and_mismatch(self):
        ok = permcheck.PathPolicy(mask_exactly="r--")
        self.assertEqual(permcheck.verify(self._facts_with(self.EFFECTIVE), ok), [])
        bad = permcheck.PathPolicy(mask_exactly="r--")
        findings = permcheck.verify(self._facts_with(self.CLIPPED), bad)
        self.assertEqual(findings[0].check, "mask_exactly")
        self.assertEqual(findings[0].actual, "---")

    def test_mask_absent_reports_absent(self):
        text = "user::rw-\ngroup::r--\nother::---\n"
        policy = permcheck.PathPolicy(mask_exactly="r--")
        findings = permcheck.verify(self._facts_with(text), policy)
        self.assertEqual(findings[0].actual, "absent")

    def test_default_acl_required_but_absent(self):
        policy = permcheck.PathPolicy(require_default_acl=True)
        findings = permcheck.verify(self._facts_with(self.EFFECTIVE), policy)
        self.assertEqual(findings[0].check, "default_acl")

    def test_default_acl_forbidden_but_present(self):
        text = self.EFFECTIVE + "default:user::rwx\ndefault:other::---\n"
        policy = permcheck.PathPolicy(require_default_acl=False)
        findings = permcheck.verify(self._facts_with(text), policy)
        self.assertEqual(findings[0].check, "default_acl")
        self.assertEqual(findings[0].actual, "present")

    def test_unresolved_named_entry_flagged_on_request(self):
        text = (
            "user::rwx\nuser:4294967295:r-x\ngroup::r-x\nmask::r-x\nother::---\n"
        )
        policy = permcheck.PathPolicy(forbid_unresolved_named=True)
        findings = permcheck.verify(self._facts_with(text), policy)
        self.assertEqual(findings[0].check, "unresolved_named")
        self.assertIn("4294967295", findings[0].actual)

    def test_unresolved_named_entry_ignored_by_default(self):
        text = (
            "user::rwx\nuser:4294967295:r-x\ngroup::r-x\nmask::r-x\nother::---\n"
        )
        self.assertEqual(
            permcheck.verify(self._facts_with(text), permcheck.PathPolicy()), []
        )

    def test_acl_policy_without_acl_data_reports_unavailable(self):
        facts = permcheck.PathFacts(
            path="/p", exists=True, mode=0o600, acl=permcheck.Acl(available=False)
        )
        policy = permcheck.PathPolicy(
            require_effective=(("user", "agent-bot", "r--"),)
        )
        findings = permcheck.verify(facts, policy)
        self.assertEqual(findings[0].check, "acl_unavailable")
        self.assertEqual(findings[0].severity, "medium")

    def test_no_acl_policy_means_no_acl_requirement(self):
        facts = permcheck.PathFacts(
            path="/p", exists=True, mode=0o600, acl=permcheck.Acl(available=False)
        )
        self.assertEqual(permcheck.verify(facts, permcheck.PathPolicy()), [])


class AclIntegrationTests(unittest.TestCase):
    """Against real ACLs, so the parser is checked on real libacl output."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="guard-acl-")
        self.root = self._tmp.name
        self.addCleanup(self._tmp.cleanup)
        if shutil.which("getfacl") is None:
            self.skipTest("getfacl not installed")
        self.path = os.path.join(self.root, "f")
        with open(self.path, "w") as handle:
            handle.write("x")
        os.chmod(self.path, 0o600)
        self.uid = os.getuid()

    def test_named_entry_becomes_effective_then_inert(self):
        if not _setfacl("-m", f"u:{self.uid}:r-x", self.path):
            self.skipTest("setfacl cannot add a named entry here")
        facts = permcheck.collect(self.path)
        named = facts.acl.named("user")
        self.assertEqual(len(named), 1)
        self.assertEqual(
            permcheck.effective_perms(named[0], facts.acl.mask), "r-x"
        )

        # Now clip the mask and re-read: same declared entry, no access.
        self.assertTrue(_setfacl("-m", "m::---", self.path))
        clipped = permcheck.collect(self.path)
        entry = clipped.acl.named("user")[0]
        self.assertEqual(entry.perms, "r-x")
        self.assertEqual(permcheck.effective_perms(entry, clipped.acl.mask), "---")

        policy = permcheck.PathPolicy(
            require_effective=(("user", entry.qualifier, "r--"),)
        )
        findings = permcheck.verify(clipped, policy)
        self.assertEqual(len(findings), 1)
        self.assertIn("clipped by mask", findings[0].message)

    def test_real_default_acl_is_detected(self):
        if not _setfacl("-d", "-m", f"u:{self.uid}:r-x", self.root):
            self.skipTest("setfacl cannot add a default entry here")
        facts = permcheck.collect(self.root)
        self.assertTrue(facts.acl.has_default)
        self.assertEqual(permcheck.verify(facts, permcheck.PathPolicy(
            require_default_acl=True, allow_world_readable=True
        )), [])

    def test_forbidden_principal_in_real_default_acl_is_detected(self):
        synthetic_uid = 424242
        if not _setfacl("-d", "-m", f"u:{synthetic_uid}:r-x", self.root):
            self.skipTest("setfacl cannot add a synthetic default entry here")
        facts = permcheck.collect(self.root)
        policy = permcheck.PathPolicy(
            forbid_named=(("user", str(synthetic_uid)),),
            allow_world_readable=True,
        )
        findings = permcheck.verify(facts, policy)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].check, "forbid_named")
        self.assertIn("default ACL", findings[0].message)

    def test_mask_only_file_has_no_named_entries(self):
        self.assertTrue(_setfacl("-m", "m::---", self.path))
        facts = permcheck.collect(self.path)
        self.assertEqual(facts.acl.named(), [])
        self.assertIsNotNone(facts.acl.mask)


class TreeAndPolicyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="guard-tree-")
        self.root = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def _write(self, rel, mode=0o600):
        full = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as handle:
            handle.write("x")
        os.chmod(full, mode)
        return full

    def test_tree_flags_only_the_loose_file(self):
        self._write("a/tight.txt", 0o600)
        loose = self._write("a/loose.txt", 0o644)
        os.chmod(self.root, 0o700)
        os.chmod(os.path.join(self.root, "a"), 0o700)
        policy = permcheck.PathPolicy(allow_world_readable=False)
        findings = permcheck.verify_tree(self.root, policy, with_acl=False)
        flagged = {f.path for f in findings if f.check == "world_readable"}
        self.assertEqual(flagged, {loose})

    def test_tree_is_deterministic(self):
        for name in ("z.txt", "a.txt", "m.txt"):
            self._write(name, 0o644)
        os.chmod(self.root, 0o700)
        policy = permcheck.PathPolicy()
        first = [f.path for f in permcheck.verify_tree(self.root, policy, False)]
        second = [f.path for f in permcheck.verify_tree(self.root, policy, False)]
        self.assertEqual(first, second)

    def test_tree_skips_dot_git(self):
        self._write(".git/config", 0o644)
        os.chmod(self.root, 0o700)
        os.chmod(os.path.join(self.root, ".git"), 0o700)
        findings = permcheck.verify_tree(self.root, permcheck.PathPolicy(), False)
        self.assertEqual([f for f in findings if ".git" in f.path], [])

    def test_secret_file_policy_rejects_group_read(self):
        path = self._write("key.pem", 0o640)
        findings = permcheck.verify_path(
            path, permcheck.SECRET_FILE_POLICY, with_acl=False
        )
        self.assertIn("mode_at_most", {f.check for f in findings})

    def test_secret_file_policy_accepts_0600(self):
        path = self._write("key.pem", 0o600)
        self.assertEqual(
            permcheck.verify_path(path, permcheck.SECRET_FILE_POLICY, with_acl=False),
            [],
        )

    def test_shared_readonly_policy_accepts_0750_dir(self):
        os.chmod(self.root, 0o750)
        self.assertEqual(
            permcheck.verify_path(
                self.root, permcheck.SHARED_READONLY_POLICY, with_acl=False
            ),
            [],
        )


class FindingFormatTests(unittest.TestCase):
    def test_format_includes_expected_and_actual(self):
        finding = permcheck.PermFinding(
            "/p", "mode_exactly", "mode does not match policy", "0600", "0644"
        )
        text = finding.format()
        self.assertIn("/p", text)
        self.assertIn("mode_exactly", text)
        self.assertIn("expected 0600", text)
        self.assertIn("actual 0644", text)

    def test_format_without_expected_actual(self):
        finding = permcheck.PermFinding("/p", "note", "something")
        self.assertNotIn("expected", finding.format())


class CliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="guard-permcli-")
        self.root = self._tmp.name
        self.addCleanup(self._tmp.cleanup)
        os.chmod(self.root, 0o700)

    def _run(self, argv):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = permcheck.main(argv)
        return code, buffer.getvalue()

    def test_clean_path_exits_zero(self):
        path = os.path.join(self.root, "f")
        with open(path, "w") as handle:
            handle.write("x")
        os.chmod(path, 0o600)
        code, out = self._run(["--mode-exactly", "600", "--no-acl", path])
        self.assertEqual(code, 0)
        self.assertIn("0 finding(s)", out)

    def test_loose_mode_exits_one(self):
        path = os.path.join(self.root, "f")
        with open(path, "w") as handle:
            handle.write("x")
        os.chmod(path, 0o666)
        code, out = self._run(["--mode-at-most", "600", "--no-acl", path])
        self.assertEqual(code, 1)
        self.assertIn("world_writable", out)

    def test_require_effective_spec_is_parsed(self):
        path = os.path.join(self.root, "f")
        with open(path, "w") as handle:
            handle.write("x")
        os.chmod(path, 0o600)
        code, out = self._run(
            ["--require-effective", "user:nobody-here:r--", path]
        )
        self.assertEqual(code, 1)
        self.assertIn("require_effective", out)

    def test_malformed_require_effective_is_rejected(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                permcheck.main(["--require-effective", "bogus", self.root])

    def test_recursive_flag_walks(self):
        sub = os.path.join(self.root, "sub")
        os.makedirs(sub)
        os.chmod(sub, 0o777)
        code, out = self._run(["--recursive", "--no-acl", self.root])
        self.assertEqual(code, 1)
        self.assertIn("world_writable", out)




# A namespace with exactly two users and one group, so resolution is tested
# against a known population rather than against whoever exists on the host.
_USERS_BY_ID = {1000: "alice", 1001: "bob"}
_GROUPS_BY_ID = {2000: "staff"}
FIXTURE_RESOLVER = permcheck.PrincipalResolver(
    user_by_id=lambda uid: _USERS_BY_ID.get(uid),
    user_by_name=lambda name: next(
        (uid for uid, n in _USERS_BY_ID.items() if n == name), None
    ),
    group_by_id=lambda gid: _GROUPS_BY_ID.get(gid),
    group_by_name=lambda name: next(
        (gid for gid, n in _GROUPS_BY_ID.items() if n == name), None
    ),
)


class PrincipalResolutionTests(unittest.TestCase):
    """Every numeric qualifier is resolved, not just 4294967295."""

    def test_a_mapped_uid_resolves(self):
        result = FIXTURE_RESOLVER.resolve("user", "1000")
        self.assertTrue(result.resolved)
        self.assertEqual(result.name, "alice")
        self.assertTrue(result.numeric)

    def test_an_unmapped_uid_that_is_not_the_famous_one_is_unresolved(self):
        """The defect: 777 is as unmapped as 4294967295 and was reported clean."""
        result = FIXTURE_RESOLVER.resolve("user", "777")
        self.assertFalse(result.resolved)
        self.assertNotEqual("777", permcheck.UNRESOLVED_QUALIFIER)

    def test_the_famous_unresolved_qualifier_still_resolves_to_nothing(self):
        result = FIXTURE_RESOLVER.resolve("user", permcheck.UNRESOLVED_QUALIFIER)
        self.assertFalse(result.resolved)

    def test_users_and_groups_use_separate_namespaces(self):
        # 2000 is a group, not a user; 1000 is a user, not a group.
        self.assertFalse(FIXTURE_RESOLVER.resolve("user", "2000").resolved)
        self.assertTrue(FIXTURE_RESOLVER.resolve("group", "2000").resolved)
        self.assertFalse(FIXTURE_RESOLVER.resolve("group", "1000").resolved)

    def test_a_known_name_resolves_to_its_id(self):
        result = FIXTURE_RESOLVER.resolve("user", "alice")
        self.assertTrue(result.resolved)
        self.assertEqual(result.identifier, 1000)
        self.assertFalse(result.numeric)

    def test_an_unknown_name_does_not_resolve(self):
        self.assertFalse(FIXTURE_RESOLVER.resolve("user", "carol").resolved)

    def test_labels_distinguish_the_two_failure_shapes(self):
        self.assertIn(
            "numeric id with no entry",
            FIXTURE_RESOLVER.resolve("user", "777").label(),
        )
        self.assertIn(
            "name with no entry", FIXTURE_RESOLVER.resolve("user", "carol").label()
        )

    def test_the_live_resolver_maps_this_process(self):
        import os
        import pwd

        uid = os.getuid()
        result = permcheck.DEFAULT_RESOLVER.resolve("user", str(uid))
        self.assertTrue(result.resolved)
        self.assertEqual(result.name, pwd.getpwuid(uid).pw_name)

    def test_entry_level_properties_split_numeric_from_named(self):
        numeric = permcheck.AclEntry("user", "777", "r--", False)
        named = permcheck.AclEntry("user", "definitely-not-a-user-xyz", "r--", False)
        self.assertTrue(numeric.is_numeric_qualifier)
        self.assertFalse(named.is_numeric_qualifier)
        self.assertTrue(numeric.is_unresolved)
        self.assertFalse(numeric.is_unknown_principal)
        self.assertFalse(named.is_unresolved)
        self.assertTrue(named.is_unknown_principal)

    def test_an_entry_without_a_qualifier_has_no_resolution(self):
        self.assertIsNone(permcheck.AclEntry("user", None, "rwx", False).resolution())
        self.assertIsNone(permcheck.AclEntry("mask", None, "r-x", False).resolution())


class DefaultAclPrincipalTests(unittest.TestCase):
    """A default entry is inherited by every file created later."""

    ACCESS_ONLY = (
        "user::rwx\nuser:777:r-x\ngroup::r-x\nmask::r-x\nother::---\n"
    )
    DEFAULT_ONLY = (
        "user::rwx\ngroup::r-x\nmask::r-x\nother::---\n"
        "default:user::rwx\ndefault:user:888:r-x\n"
        "default:group::r-x\ndefault:mask::r-x\ndefault:other::---\n"
    )
    BOTH = (
        "user::rwx\nuser:777:r-x\ngroup::r-x\nmask::r-x\nother::---\n"
        "default:user::rwx\ndefault:user:888:r-x\n"
        "default:group::r-x\ndefault:mask::r-x\ndefault:other::---\n"
    )

    def facts(self, text):
        return permcheck.PathFacts(
            path="/fixture",
            exists=True,
            is_symlink=False,
            is_dir=True,
            mode=0o750,
            uid=1000,
            owner="alice",
            gid=2000,
            group="staff",
            acl=permcheck.parse_getfacl(text),
        )

    def policy(self):
        return permcheck.PathPolicy(
            forbid_unresolved_named=True, resolver=FIXTURE_RESOLVER
        )

    def test_named_does_not_include_default_entries(self):
        acl = permcheck.parse_getfacl(self.BOTH)
        self.assertEqual([e.qualifier for e in acl.named()], ["777"])
        self.assertEqual([e.qualifier for e in acl.named_default()], ["888"])
        self.assertEqual(
            sorted(e.qualifier for e in acl.all_named()), ["777", "888"]
        )

    def test_an_unmapped_access_entry_is_reported(self):
        findings = permcheck.verify(self.facts(self.ACCESS_ONLY), self.policy())
        checks = [f.check for f in findings]
        self.assertIn("unresolved_named", checks)
        self.assertIn("access ACL", findings[checks.index("unresolved_named")].message)

    def test_an_unmapped_default_entry_is_reported(self):
        """The gap: the old check read only the access ACL, so this was clean."""
        findings = [
            f
            for f in permcheck.verify(self.facts(self.DEFAULT_ONLY), self.policy())
            if f.check == "unresolved_named"
        ]
        self.assertEqual(len(findings), 1)
        self.assertIn("default ACL", findings[0].message)
        self.assertIn("888", findings[0].actual)

    def test_both_acls_are_reported_independently(self):
        findings = [
            f
            for f in permcheck.verify(self.facts(self.BOTH), self.policy())
            if f.check == "unresolved_named"
        ]
        self.assertEqual(len(findings), 2)
        self.assertEqual(
            sorted("default" in f.message for f in findings), [False, True]
        )

    def test_a_resolvable_default_entry_is_not_reported(self):
        text = (
            "user::rwx\ngroup::r-x\nmask::r-x\nother::---\n"
            "default:user::rwx\ndefault:user:1001:r-x\n"
            "default:group::r-x\ndefault:mask::r-x\ndefault:other::---\n"
        )
        findings = [
            f
            for f in permcheck.verify(self.facts(text), self.policy())
            if f.check in ("unresolved_named", "unknown_named_principal")
        ]
        self.assertEqual(findings, [])

    def test_an_unknown_named_principal_is_its_own_check(self):
        text = (
            "user::rwx\nuser:carol:r-x\ngroup::r-x\nmask::r-x\nother::---\n"
        )
        findings = [
            f for f in permcheck.verify(self.facts(text), self.policy())
        ]
        checks = {f.check for f in findings}
        self.assertIn("unknown_named_principal", checks)
        self.assertNotIn("unresolved_named", checks)

    def test_an_unmapped_default_group_is_reported(self):
        text = (
            "user::rwx\ngroup::r-x\nmask::r-x\nother::---\n"
            "default:user::rwx\ndefault:group::r-x\ndefault:group:4242:r--\n"
            "default:mask::r-x\ndefault:other::---\n"
        )
        findings = [
            f
            for f in permcheck.verify(self.facts(text), self.policy())
            if f.check == "unresolved_named"
        ]
        self.assertEqual(len(findings), 1)
        self.assertIn("4242", findings[0].actual)

    def test_the_finding_names_both_the_entry_and_the_resolution(self):
        findings = [
            f
            for f in permcheck.verify(self.facts(self.ACCESS_ONLY), self.policy())
            if f.check == "unresolved_named"
        ]
        self.assertIn("user:777:r-x", findings[0].actual)
        self.assertIn("unresolved", findings[0].actual)

    def test_nothing_is_reported_when_the_policy_does_not_ask(self):
        findings = permcheck.verify(
            self.facts(self.BOTH),
            permcheck.PathPolicy(resolver=FIXTURE_RESOLVER),
        )
        self.assertEqual(
            [f for f in findings if "named" in f.check], []
        )


class ModeArgumentTests(unittest.TestCase):
    def test_bad_octal_modes_are_usage_errors(self):
        for bad in ("999", "abc", "17777"):
            with self.subTest(bad=bad), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as ctx:
                permcheck.main(["--mode-at-most", bad, "/"])
            self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
