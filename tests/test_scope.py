import pytest

from bounty_agent.scope import Action, Policy, ScopeViolation, check, is_allowed

REPO = "https://github.com/example/protocol"


def good_policy(**overrides):
    base = dict(
        program="example",
        human_confirmed=True,
        ai_allowed=True,
        in_scope=[REPO, "eth:0xABCDEF*"],
        out_of_scope=["eth:0xabcdef00"],
        allowed_actions=[Action.CLONE_SOURCE, Action.LOCAL_ANALYSIS, Action.LOCAL_FORK],
    )
    base.update(overrides)
    return Policy(**base)


def test_allowed_when_everything_lines_up():
    check(good_policy(), Action.CLONE_SOURCE, REPO + ".git/")  # normalized


def test_unconfirmed_policy_denied():
    with pytest.raises(ScopeViolation, match="confirmed"):
        check(good_policy(human_confirmed=False), Action.CLONE_SOURCE, REPO)


@pytest.mark.parametrize("ai", [None, False])
def test_unknown_or_banned_ai_denied(ai):
    with pytest.raises(ScopeViolation, match="AI"):
        check(good_policy(ai_allowed=ai), Action.CLONE_SOURCE, REPO)


def test_unlisted_action_denied():
    with pytest.raises(ScopeViolation, match="allowed actions"):
        check(good_policy(), Action.LOCAL_BUILD, REPO)


@pytest.mark.parametrize("action", [Action.LIVE_REQUEST, Action.SUBMIT])
def test_forbidden_actions_denied_even_if_policy_lists_them(action):
    p = good_policy(allowed_actions=list(Action))
    with pytest.raises(ScopeViolation, match="never"):
        check(p, action, REPO)


def test_unlisted_asset_denied():
    assert not is_allowed(good_policy(), Action.CLONE_SOURCE, "https://github.com/example/other")


def test_glob_and_case_insensitive_addresses():
    assert is_allowed(good_policy(), Action.LOCAL_FORK, "eth:0xabcdef12")


def test_out_of_scope_beats_in_scope():
    with pytest.raises(ScopeViolation, match="out of scope"):
        check(good_policy(), Action.LOCAL_FORK, "eth:0xABCDEF00")


def test_json_roundtrip():
    p = good_policy()
    assert Policy.from_json(p.to_json()) == p
