# PROVENANCE (mirror of .provenance/ledger.jsonl; ledger wins)
# written-by: unknown (pre-provenance) | 2026-10-09 | f032f17
# modified-by: codex/gpt-5.6-sol | 2026-10-26 | 1aaa682 | provenance block added
# reviewed-by: claude-code/claude-opus-5-5 | 2026-10-26 | APPROVE
# reviewed-by: grok-build/grok-4.7 | 2026-10-26 | APPROVE
# END PROVENANCE
"""Tests for guardlib.gate.

Covers the five refused classes, the ordinary-allow classes, the REVIEW
outcome that keeps ambiguity from resolving to either extreme, and the
ordering property that a risky field cannot be smuggled in under a benign kind.
"""

import contextlib
import io
import json
import os
import pwd
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from guardlib.gate import (  # noqa: E402
    Action,
    ActionKind,
    Decision,
    Judgement,
    PolicyGate,
    TrustedContext,
    evaluate,
    main,
    resolve_trusted_context,
)


class DecisionTests(unittest.TestCase):
    def test_only_allow_is_permitted(self):
        self.assertTrue(Decision.ALLOW.permitted)
        self.assertFalse(Decision.DENY.permitted)
        self.assertFalse(Decision.REVIEW.permitted)

    def test_review_is_distinct_from_both(self):
        self.assertNotEqual(Decision.REVIEW, Decision.ALLOW)
        self.assertNotEqual(Decision.REVIEW, Decision.DENY)

    def test_judgement_format_carries_rule_and_reason(self):
        judgement = Judgement(Decision.DENY, "nope", "some_rule")
        text = judgement.format()
        self.assertIn("DENY", text)
        self.assertIn("some_rule", text)
        self.assertIn("nope", text)


class SpendTests(unittest.TestCase):
    def test_spend_kind_is_denied(self):
        result = evaluate(Action(kind=ActionKind.SPEND, description="buy a license"))
        self.assertIs(result.decision, Decision.DENY)
        self.assertEqual(result.rule_id, "spend")

    def test_amount_alone_is_denied_even_under_a_benign_kind(self):
        """A risky field must not pass because the kind looks harmless."""
        result = evaluate(
            Action(kind=ActionKind.WRITE, amount=49.0, currency="USD")
        )
        self.assertIs(result.decision, Decision.DENY)
        self.assertEqual(result.rule_id, "spend")

    def test_amount_appears_in_the_reason(self):
        result = evaluate(Action(kind=ActionKind.SPEND, amount=12.5, currency="EUR"))
        self.assertIn("12.5", result.reason)
        self.assertIn("EUR", result.reason)

    def test_missing_currency_is_named_not_guessed(self):
        result = evaluate(Action(kind=ActionKind.SPEND, amount=5.0))
        self.assertIn("unspecified currency", result.reason)

    def test_zero_amount_is_still_a_spend(self):
        """0.0 is not None; a declared amount is a money action."""
        result = evaluate(Action(kind=ActionKind.READ, amount=0.0))
        self.assertIs(result.decision, Decision.DENY)

    def test_payment_wording_without_structure_is_review(self):
        result = evaluate(
            Action(kind=ActionKind.OTHER, description="set up the subscription")
        )
        self.assertIs(result.decision, Decision.REVIEW)
        self.assertEqual(result.rule_id, "spend_ambiguous")

    def test_prose_about_money_does_not_allow(self):
        result = evaluate(Action(kind=ActionKind.OTHER, description="refactor billing"))
        self.assertIsNot(result.decision, Decision.ALLOW)


class MessageAndImpersonationTests(unittest.TestCase):
    def test_send_message_kind_is_denied(self):
        result = evaluate(Action(kind=ActionKind.SEND_MESSAGE, target="slack"))
        self.assertIs(result.decision, Decision.DENY)
        self.assertEqual(result.rule_id, "send_message")

    def test_acting_as_the_owner_is_denied(self):
        result = evaluate(Action(kind=ActionKind.WRITE, principal="Owner"))
        self.assertIs(result.decision, Decision.DENY)
        self.assertEqual(result.rule_id, "impersonation")

    def test_impersonation_check_is_case_insensitive(self):
        for name in ("owner", "OWNER", " Owner "):
            with self.subTest(name=name):
                result = evaluate(Action(kind=ActionKind.READ, principal=name))
                self.assertEqual(result.rule_id, "impersonation")

    def test_other_protected_principals(self):
        for name in ("owner", "root"):
            with self.subTest(name=name):
                self.assertEqual(
                    evaluate(Action(principal=name)).rule_id, "impersonation"
                )

    def test_impersonation_outranks_ordinary_work(self):
        """Ordering property: the benign kind does not rescue the action."""
        result = evaluate(Action(kind=ActionKind.COMMIT, principal="root"))
        self.assertIs(result.decision, Decision.DENY)

    def test_ordinary_principal_is_not_impersonation(self):
        result = evaluate(Action(kind=ActionKind.READ, principal="claude"))
        self.assertIs(result.decision, Decision.ALLOW)

    def test_message_wording_without_structure_is_review(self):
        result = evaluate(Action(description="notify the team in slack"))
        self.assertIs(result.decision, Decision.REVIEW)
        self.assertEqual(result.rule_id, "send_message_ambiguous")


class DeleteTests(unittest.TestCase):
    """Ownership is measured from the inode, never taken from the request.

    The fixture tree is owned by whoever runs the suite, so no test needs root
    and none changes any file's owner. "Someone else's work" is produced by
    giving the gate a trusted identity with a different uid, which is the same
    comparison the real gate makes.
    """

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = os.path.join(self.root, "work.txt")
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write("content\n")
        self.missing = os.path.join(self.root, "absent.txt")
        self.real_uid = os.lstat(self.path).st_uid
        self.mine = TrustedContext(
            uid=self.real_uid, username=pwd.getpwuid(self.real_uid).pw_name
        )
        # A different uid: the same file is then another principal's work.
        self.stranger = TrustedContext(uid=self.real_uid + 1, username="stranger")

    def judge(self, action, trusted=None):
        return PolicyGate(trusted=trusted or self.mine).evaluate(action)

    def test_deleting_a_file_the_gate_owns_is_allowed(self):
        result = self.judge(Action(kind=ActionKind.DELETE, target=self.path))
        self.assertIs(result.decision, Decision.ALLOW)
        self.assertEqual(result.rule_id, "delete_own_work")

    def test_deleting_a_file_owned_by_another_uid_is_denied(self):
        result = self.judge(
            Action(kind=ActionKind.DELETE, target=self.path), self.stranger
        )
        self.assertIs(result.decision, Decision.DENY)
        self.assertEqual(result.rule_id, "delete_others_work")
        self.assertIn(str(self.real_uid), result.reason)

    def test_a_forged_matching_owner_and_actor_pair_does_not_allow(self):
        """The defect this rule exists to close.

        Both fields are caller-controlled, so a request can always make them
        agree. Agreement between two claims is not evidence about the target.
        """
        result = self.judge(
            Action(
                kind=ActionKind.DELETE,
                target=self.path,
                owner="stranger",
                actor="stranger",
            ),
            self.stranger,
        )
        self.assertIsNot(result.decision, Decision.ALLOW)
        self.assertIs(result.decision, Decision.DENY)

    def test_a_forged_pair_cannot_authorise_a_target_owned_by_someone_else(self):
        result = self.judge(
            Action(
                kind=ActionKind.DELETE,
                target=self.path,
                owner="stranger",
                actor="stranger",
            ),
            TrustedContext(uid=self.real_uid + 2, username="stranger"),
        )
        self.assertIs(result.decision, Decision.DENY)
        self.assertEqual(result.rule_id, "delete_others_work")

    def test_a_claim_can_only_tighten_never_loosen(self):
        """Same target, same trusted identity; only the claim differs."""
        bare = self.judge(Action(kind=ActionKind.DELETE, target=self.path))
        claimed = self.judge(
            Action(kind=ActionKind.DELETE, target=self.path, owner="somebody-else")
        )
        self.assertIs(bare.decision, Decision.ALLOW)
        self.assertIs(claimed.decision, Decision.DENY)

    def test_declared_owner_matching_the_trusted_name_still_needs_the_inode(self):
        result = self.judge(
            Action(
                kind=ActionKind.DELETE,
                target=self.path,
                owner=self.mine.username,
            ),
            self.stranger,
        )
        self.assertIs(result.decision, Decision.DENY)

    def test_declared_actor_that_is_not_the_trusted_identity_is_denied(self):
        result = self.judge(
            Action(kind=ActionKind.DELETE, target=self.path, actor="codex")
        )
        self.assertIs(result.decision, Decision.DENY)
        self.assertEqual(result.rule_id, "delete_actor_mismatch")

    def test_the_numeric_uid_is_an_accepted_spelling(self):
        result = self.judge(
            Action(
                kind=ActionKind.DELETE,
                target=self.path,
                actor=str(self.real_uid),
                owner=str(self.real_uid),
            )
        )
        self.assertIs(result.decision, Decision.ALLOW)

    def test_owner_claim_comparison_is_case_insensitive(self):
        result = self.judge(
            Action(
                kind=ActionKind.DELETE,
                target=self.path,
                owner=self.mine.username.upper(),
            )
        )
        self.assertIs(result.decision, Decision.ALLOW)

    def test_delete_without_a_target_is_review_not_allow(self):
        result = self.judge(Action(kind=ActionKind.DELETE))
        self.assertIs(result.decision, Decision.REVIEW)
        self.assertEqual(result.rule_id, "delete_target_unverifiable")

    def test_delete_of_a_missing_path_is_review_not_allow(self):
        result = self.judge(Action(kind=ActionKind.DELETE, target=self.missing))
        self.assertIs(result.decision, Decision.REVIEW)
        self.assertEqual(result.rule_id, "delete_owner_unverifiable")
        self.assertIn("unverifiable", result.reason)

    def test_unverifiable_ownership_names_the_error(self):
        result = self.judge(Action(kind=ActionKind.DELETE, target=self.missing))
        self.assertIn("No such file", result.reason)

    def test_irreversible_delete_of_own_work_is_review(self):
        result = self.judge(
            Action(kind=ActionKind.DELETE, target=self.path, reversible=False)
        )
        self.assertIs(result.decision, Decision.REVIEW)
        self.assertEqual(result.rule_id, "delete_irreversible")

    def test_a_symlink_is_judged_by_the_links_own_owner(self):
        link = os.path.join(self.root, "link")
        os.symlink(self.path, link)
        result = self.judge(Action(kind=ActionKind.DELETE, target=link))
        self.assertIs(result.decision, Decision.ALLOW)

    def test_a_directory_the_gate_owns_is_allowed(self):
        result = self.judge(Action(kind=ActionKind.DELETE, target=self.root))
        self.assertIs(result.decision, Decision.ALLOW)

    def test_an_unmapped_owner_uid_is_reported_as_unmapped(self):
        """A uid with no passwd entry is named, not silently treated as absent."""
        owner = PolicyGate(trusted=self.mine).trusted.owner_of(self.path)
        self.assertTrue(owner.verified)
        unmapped = type(owner)(uid=4294967295, username=None, error=None)
        self.assertIn("unmapped", unmapped.label())


class TrustedContextTests(unittest.TestCase):
    def test_the_gate_resolves_its_own_identity(self):
        trusted = resolve_trusted_context()
        self.assertEqual(trusted.uid, os.getuid())
        self.assertIn(str(trusted.uid), trusted.names() | {str(trusted.uid)})

    def test_the_identity_is_not_taken_from_the_action(self):
        gate = PolicyGate()
        self.assertEqual(gate.trusted.uid, os.getuid())
        gate.evaluate(Action(kind=ActionKind.DELETE, actor="root", owner="root"))
        self.assertEqual(gate.trusted.uid, os.getuid())

    def test_names_include_the_numeric_uid(self):
        trusted = TrustedContext(uid=4242, username="someone")
        self.assertEqual(trusted.names(), frozenset({"someone", "4242"}))

    def test_owner_of_a_missing_path_is_unverified(self):
        trusted = resolve_trusted_context()
        owner = trusted.owner_of("/nonexistent/guard/probe")
        self.assertFalse(owner.verified)
        self.assertIsNotNone(owner.error)


class ActivationTests(unittest.TestCase):
    def test_activate_service_kind_is_denied(self):
        result = evaluate(Action(kind=ActionKind.ACTIVATE_SERVICE, target="api"))
        self.assertIs(result.decision, Decision.DENY)
        self.assertEqual(result.rule_id, "activate_service")

    def test_systemd_target_is_denied_under_a_benign_kind(self):
        result = evaluate(
            Action(kind=ActionKind.WRITE, target="/etc/systemd/system/x.service")
        )
        self.assertIs(result.decision, Decision.DENY)
        self.assertEqual(result.rule_id, "service_manager_target")
        self.assertIn("systemd", result.reason)

    def test_each_service_manager_is_recognised(self):
        for manager in ("systemctl", "launchd", "crontab", "timer"):
            with self.subTest(manager=manager):
                result = evaluate(Action(target=f"/x/{manager}/y"))
                self.assertIs(result.decision, Decision.DENY)

    def test_activation_wording_is_review(self):
        result = evaluate(Action(description="enable the daemon later"))
        self.assertIs(result.decision, Decision.REVIEW)
        self.assertEqual(result.rule_id, "activate_ambiguous")

    def test_ordinary_write_to_a_normal_path_is_allowed(self):
        result = evaluate(Action(kind=ActionKind.WRITE, target="guard/guardlib/x.py"))
        self.assertIs(result.decision, Decision.ALLOW)


class AccountAndCredentialTests(unittest.TestCase):
    def test_account_change_is_denied(self):
        result = evaluate(Action(kind=ActionKind.ACCOUNT_CHANGE))
        self.assertIs(result.decision, Decision.DENY)
        self.assertEqual(result.rule_id, "account_change")

    def test_credential_change_is_denied(self):
        result = evaluate(Action(kind=ActionKind.CREDENTIAL_CHANGE))
        self.assertIs(result.decision, Decision.DENY)
        self.assertEqual(result.rule_id, "credential_change")

    def test_rotation_is_covered_by_the_reason(self):
        result = evaluate(Action(kind=ActionKind.CREDENTIAL_CHANGE))
        self.assertIn("rotation", result.reason)

    def test_credential_wording_is_review(self):
        result = evaluate(Action(description="read the api key from the env"))
        self.assertIs(result.decision, Decision.REVIEW)
        self.assertEqual(result.rule_id, "credential_ambiguous")

    def test_credential_wording_outranks_ordinary_read(self):
        result = evaluate(
            Action(kind=ActionKind.READ, description="print the password file")
        )
        self.assertIs(result.decision, Decision.REVIEW)


class OrdinaryWorkTests(unittest.TestCase):
    def test_each_ordinary_kind_is_allowed_with_a_reason(self):
        kinds = (
            ActionKind.READ,
            ActionKind.WRITE,
            ActionKind.RUN_TESTS,
            ActionKind.BUILD,
            ActionKind.COMMIT,
            ActionKind.PUSH,
            ActionKind.INSTALL_DEV_DEPENDENCY,
        )
        for kind in kinds:
            with self.subTest(kind=kind):
                result = evaluate(Action(kind=kind))
                self.assertIs(result.decision, Decision.ALLOW)
                self.assertTrue(result.reason)

    def test_unmatched_action_defaults_to_allow(self):
        result = evaluate(Action(kind=ActionKind.OTHER, description="tidy the imports"))
        self.assertIs(result.decision, Decision.ALLOW)
        self.assertEqual(result.rule_id, "default_allow")

    def test_every_judgement_has_a_nonempty_reason(self):
        samples = [
            Action(kind=ActionKind.SPEND),
            Action(kind=ActionKind.SEND_MESSAGE),
            Action(kind=ActionKind.DELETE, owner="codex"),
            Action(kind=ActionKind.ACTIVATE_SERVICE),
            Action(kind=ActionKind.ACCOUNT_CHANGE),
            Action(kind=ActionKind.CREDENTIAL_CHANGE),
            Action(kind=ActionKind.READ),
            Action(kind=ActionKind.OTHER),
        ]
        for action in samples:
            with self.subTest(kind=action.kind):
                self.assertTrue(evaluate(action).reason.strip())


class GateObjectTests(unittest.TestCase):
    def test_permits_matches_decision(self):
        gate = PolicyGate()
        self.assertTrue(gate.permits(Action(kind=ActionKind.READ)))
        self.assertFalse(gate.permits(Action(kind=ActionKind.SPEND)))

    def test_check_is_an_alias(self):
        gate = PolicyGate()
        action = Action(kind=ActionKind.SPEND)
        self.assertEqual(gate.check(action).rule_id, gate.evaluate(action).rule_id)

    def test_evaluate_all_preserves_order(self):
        gate = PolicyGate()
        actions = [
            Action(kind=ActionKind.READ),
            Action(kind=ActionKind.SPEND),
            Action(kind=ActionKind.BUILD),
        ]
        decisions = [j.decision for j in gate.evaluate_all(actions)]
        self.assertEqual(
            decisions, [Decision.ALLOW, Decision.DENY, Decision.ALLOW]
        )

    def test_first_matching_rule_wins(self):
        def always_deny(action, trusted):
            return Judgement(Decision.DENY, "first", "first_rule")

        def never_reached(action, trusted):  # pragma: no cover
            raise AssertionError("second rule should not run")

        gate = PolicyGate([always_deny, never_reached])
        self.assertEqual(gate.evaluate(Action()).rule_id, "first_rule")

    def test_custom_rule_list_replaces_defaults(self):
        gate = PolicyGate([lambda action, trusted: None])
        result = gate.evaluate(Action(kind=ActionKind.SPEND))
        # With spend rules removed, the risky-class fallthrough still denies.
        self.assertIs(result.decision, Decision.DENY)
        self.assertEqual(result.rule_id, "risky_fallthrough")

    def test_empty_rule_list_still_denies_risky_kinds(self):
        gate = PolicyGate([])
        self.assertIs(
            gate.evaluate(Action(kind=ActionKind.DELETE)).decision, Decision.DENY
        )

    def test_empty_rule_list_allows_ordinary_kinds(self):
        gate = PolicyGate([])
        self.assertIs(
            gate.evaluate(Action(kind=ActionKind.READ)).decision, Decision.ALLOW
        )


class RiskyClassCoverageTests(unittest.TestCase):
    def test_no_risky_kind_can_reach_allow_under_default_rules(self):
        """Every named risky class must be refused or sent to review."""
        from guardlib.gate import RISKY_KINDS

        for kind in sorted(RISKY_KINDS, key=lambda k: k.value):
            with self.subTest(kind=kind):
                result = evaluate(Action(kind=kind))
                self.assertIn(
                    result.decision, (Decision.DENY, Decision.REVIEW), kind.value
                )

    def test_delete_is_the_only_risky_kind_with_a_conditional_allow(self):
        """And its allowance rests on a measured target, not on a claim."""
        from guardlib.gate import RISKY_KINDS

        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        target = os.path.join(root, "mine.txt")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("x\n")
        allowed = [
            kind
            for kind in RISKY_KINDS
            if evaluate(Action(kind=kind, target=target)).decision is Decision.ALLOW
        ]
        self.assertEqual(allowed, [ActionKind.DELETE])


class CliTests(unittest.TestCase):
    def _run(self, argv):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(argv)
        return code, buffer.getvalue()

    def test_allow_exits_zero(self):
        code, out = self._run(["--kind", "read"])
        self.assertEqual(code, 0)
        self.assertIn("ALLOW", out)

    def test_deny_exits_one(self):
        code, out = self._run(["--kind", "spend", "--amount", "10", "--currency", "USD"])
        self.assertEqual(code, 1)
        self.assertIn("DENY", out)

    def test_review_exits_two(self):
        code, out = self._run(
            ["--kind", "delete", "--target", "/nonexistent/guard/probe"]
        )
        self.assertEqual(code, 2)
        self.assertIn("REVIEW", out)

    def test_json_output_is_machine_readable(self):
        _, out = self._run(["--kind", "spend", "--json"])
        payload = json.loads(out)
        self.assertEqual(payload["decision"], "DENY")
        self.assertEqual(payload["rule_id"], "spend")
        self.assertTrue(payload["reason"])

    def test_unknown_kind_is_rejected_with_the_valid_list(self):
        buffer = io.StringIO()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(buffer):
                main(["--kind", "launch_missiles"])
        self.assertIn("unknown --kind", buffer.getvalue())

    def test_irreversible_flag_is_honoured(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        target = os.path.join(root, "mine.txt")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("x\n")
        code, out = self._run(
            ["--kind", "delete", "--target", target, "--irreversible"]
        )
        self.assertEqual(code, 2)
        self.assertIn("irreversible", out)

    def test_kind_is_case_insensitive_and_bad_kinds_are_usage_errors(self):
        self.assertEqual(self._run(["--kind", "READ"])[0], 0)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            main(["--kind", "teleport"])
        self.assertEqual(ctx.exception.code, 2)

    def test_principal_flag_triggers_impersonation_rule(self):
        code, out = self._run(["--kind", "read", "--principal", "owner"])
        self.assertEqual(code, 1)
        self.assertIn("impersonation", out)


class ProtectedPrincipalConfigTests(unittest.TestCase):
    """The protected set is operator configuration: argument, env, or default."""

    def test_default_set_is_generic(self):
        from guardlib.gate import DEFAULT_PROTECTED_PRINCIPALS
        self.assertEqual(DEFAULT_PROTECTED_PRINCIPALS, frozenset({"owner", "root"}))

    def test_constructor_argument_replaces_the_default(self):
        gate = PolicyGate(protected_principals=["Alice", " ops-lead "])
        self.assertEqual(gate.evaluate(Action(principal="alice")).rule_id, "impersonation")
        self.assertEqual(gate.evaluate(Action(principal="OPS-LEAD")).rule_id, "impersonation")
        self.assertIsNot(gate.evaluate(Action(principal="root")).decision, Decision.DENY)

    def test_environment_variable_sets_the_process_default(self):
        from guardlib.gate import protected_principals_from_env
        self.assertEqual(
            protected_principals_from_env({"GUARD_PROTECTED_PRINCIPALS": "Alice, bob ,,"}),
            frozenset({"alice", "bob"}),
        )

    def test_empty_environment_value_keeps_the_default(self):
        from guardlib.gate import DEFAULT_PROTECTED_PRINCIPALS, protected_principals_from_env
        for raw in ("", " ", ",,"):
            with self.subTest(raw=raw):
                self.assertEqual(
                    protected_principals_from_env({"GUARD_PROTECTED_PRINCIPALS": raw}),
                    DEFAULT_PROTECTED_PRINCIPALS,
                )

    def test_environment_is_read_when_a_gate_is_built(self):
        from unittest import mock
        with mock.patch.dict(os.environ, {"GUARD_PROTECTED_PRINCIPALS": "alice"}):
            gate = PolicyGate()
        self.assertEqual(gate.evaluate(Action(principal="Alice")).rule_id, "impersonation")

    def test_explicit_trusted_context_can_take_an_override(self):
        trusted = TrustedContext(uid=12345, username="tester")
        gate = PolicyGate(trusted=trusted, protected_principals=["alice"])
        self.assertEqual(gate.trusted.uid, 12345)
        self.assertEqual(gate.evaluate(Action(principal="alice")).rule_id, "impersonation")

    def test_hand_built_context_is_normalised(self):
        trusted = TrustedContext(uid=12345, username="tester", protected_principals={" Alice "})
        self.assertEqual(trusted.protected_principals, frozenset({"alice"}))
        gate = PolicyGate(trusted=trusted)
        self.assertEqual(gate.evaluate(Action(principal="ALICE")).rule_id, "impersonation")

    def test_cli_protect_flag(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["--kind", "read", "--principal", "alice", "--protect", "alice"])
        self.assertEqual(code, 1)
        self.assertIn("impersonation", buf.getvalue())




class KindValidationTests(unittest.TestCase):
    """A kind arrives from argv or JSON, so it is resolved, never trusted."""

    def test_lowercase_string_resolves(self):
        self.assertIs(Action(kind="spend").kind, ActionKind.SPEND)

    def test_uppercase_string_resolves_instead_of_falling_through(self):
        action = Action(kind="SPEND")
        self.assertIs(action.kind, ActionKind.SPEND)
        self.assertIs(evaluate(action).decision, Decision.DENY)

    def test_surrounding_whitespace_is_tolerated(self):
        self.assertIs(Action(kind=" Delete ").kind, ActionKind.DELETE)

    def test_unknown_string_is_denied_not_crashed(self):
        action = Action(kind="launch_missiles")
        self.assertIs(action.kind, ActionKind.UNKNOWN)
        result = evaluate(action)
        self.assertIs(result.decision, Decision.DENY)
        self.assertEqual(result.rule_id, "unknown_kind")

    def test_the_refusal_names_the_declared_value(self):
        self.assertIn("launch_missiles", evaluate(Action(kind="launch_missiles")).reason)

    def test_non_string_kinds_are_denied(self):
        for value in (42, None, 3.5, ["spend"], {"kind": "spend"}, object()):
            with self.subTest(value=type(value).__name__):
                action = Action(kind=value)
                self.assertIs(action.kind, ActionKind.UNKNOWN)
                self.assertIs(evaluate(action).decision, Decision.DENY)

    def test_an_unknown_kind_cannot_borrow_a_benign_description(self):
        result = evaluate(
            Action(kind="reed", description="just reading a file", target="a.txt")
        )
        self.assertIs(result.decision, Decision.DENY)
        self.assertEqual(result.rule_id, "unknown_kind")

    def test_unknown_kind_is_refused_even_with_no_rules(self):
        self.assertIs(
            PolicyGate([]).evaluate(Action(kind="nonsense")).decision, Decision.DENY
        )

    def test_enum_members_pass_through_unchanged(self):
        for kind in ActionKind:
            with self.subTest(kind=kind):
                self.assertIs(Action(kind=kind).kind, kind)

    def test_coerce_kind_is_usable_on_its_own(self):
        from guardlib.gate import coerce_kind

        self.assertIs(coerce_kind("PUSH"), ActionKind.PUSH)
        self.assertIs(coerce_kind("nope"), ActionKind.UNKNOWN)

    def test_declared_kind_is_recorded(self):
        self.assertEqual(Action(kind="SPEND").declared_kind, "SPEND")

    def test_unknown_is_in_the_risky_set(self):
        from guardlib.gate import RISKY_KINDS

        self.assertIn(ActionKind.UNKNOWN, RISKY_KINDS)


if __name__ == "__main__":
    unittest.main()
