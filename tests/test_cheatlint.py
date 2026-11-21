"""Seeded cheating PoCs must be caught; honest ones must pass."""

from bounty_agent.validate import has_blocking, lint_source

HONEST = """
contract ExploitTest is Test {
    function test_exploit() public {
        vm.startPrank(attacker);
        vm.deal(attacker, 1 ether);
        vault.deposit{value: 1 ether}();
        vault.withdrawTwice();
        vm.stopPrank();
        assertGt(attacker.balance, 1 ether);
    }
}
"""


def rules(src):
    return {(f.rule, f.severity) for f in lint_source(src)}


def test_honest_poc_has_no_blocking_flags():
    flags = lint_source(HONEST)
    assert not has_blocking(flags)
    assert rules(HONEST) == {("deal", "info")}  # capital is still surfaced for review


def test_privileged_prank_caught():
    for src in ["vm.prank(owner);", "vm.startPrank(vault.owner());", "vm.prank(address(timelock));", "vm.prank(GOVERNANCE);"]:
        assert ("privileged-prank", "high") in rules(src), src


def test_storage_mock_and_etch_caught():
    src = "vm.store(address(vault), bytes32(0), bytes32(uint256(1)));\nvm.mockCall(oracle, data, ret);\nvm.etch(target, code);"
    assert {("storage-write", "high"), ("mock-call", "high"), ("code-etch", "high")} <= rules(src)


def test_unbounded_deal_caught():
    assert ("unbounded-deal", "high") in rules("deal(address(token), attacker, type(uint256).max);")


def test_comments_are_ignored():
    src = "// vm.prank(owner);\n/* vm.store(a, b, c);\n vm.etch(x, y); */\nuint x = 1;"
    assert lint_source(src) == []


def test_justified_flag_is_kept_but_not_blocking():
    src = "// cheatlint-allow: privileged-prank attacker became owner via the initializer bug above\nvm.prank(owner);"
    flags = lint_source(src)
    assert [(f.rule, f.severity) for f in flags] == [("privileged-prank", "allowed")]
    assert "initializer bug" in flags[0].reason
    assert not has_blocking(flags)


def test_allow_comment_for_a_different_rule_does_not_excuse():
    src = "vm.prank(owner); // cheatlint-allow: deal not relevant"
    assert has_blocking(lint_source(src))
