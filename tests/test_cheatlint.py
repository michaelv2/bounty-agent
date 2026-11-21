"""Seeded cheating PoCs must be caught; honest ones must pass."""

import pytest

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


def test_ffi_caught():
    assert ("ffi", "high") in rules('string[] memory c = new string[](1); bytes memory r = vm.ffi(c);')


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


# ---- bypasses found by the 2026-11-21 security review (M5) ----

def test_multiline_call_is_caught():
    assert ("privileged-prank", "high") in rules("vm.prank(\n    owner\n);")


def test_comment_markers_inside_strings_cannot_hide_code():
    assert ("storage-write", "high") in rules('string memory u = "http://x"; vm.store(a, b, c);')
    src = 'string memory a = "/*"; vm.etch(t, code); string memory b = "*/";'
    assert ("code-etch", "high") in rules(src)


def test_ffi_cannot_be_justified_away():
    src = "// cheatlint-allow: ffi I really need it\nvm.ffi(cmd);"
    assert has_blocking(lint_source(src))


@pytest.mark.parametrize("src, rule", [
    ("vm.skip(true);", "vacuous-pass"),
    ("vm.assume(false);", "vacuous-pass"),
    ("hoax(owner);", "privileged-prank"),
    ("vm.changePrank(admin);", "privileged-prank"),
    ("stdstore.target(address(v)).sig(\"owner()\").checked_write(attacker);", "storage-write"),
    ("vm .store(a, b, c);", "storage-write"),
    ("hevm.store(a, b, c);", "storage-write"),
    ("deployCodeTo(\"Fake.sol\", target);", "code-etch"),
    ("vm.mockFunction(a, b, c);", "mock-call"),
    ("vm.setEnv(\"X\", \"1\");", "environment"),
    ("vm.createSelectFork(\"mainnet\");", "environment"),
    ("vm.writeFile(\"out\", data);", "environment"),
    ("Vm h = Vm(address(uint160(uint256(keccak256(\"hevm cheat code\")))));", "raw-cheatcode"),
    ("address(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D).call(data);", "raw-cheatcode"),
])
def test_more_cheats_caught(src, rule):
    assert (rule, "high") in rules(src), src


def test_realistic_actions_are_info_not_blocking():
    src = "vm.warp(block.timestamp + 1 days);\nvm.roll(block.number + 10);\nskip(3600);"
    flags = lint_source(src)
    assert flags and not has_blocking(flags)


# ---- bug hunt 2026-11-21: aliasing the cheatcode handle ----

@pytest.mark.parametrize("src, rule", [
    ("Vm v = vm;\nv.store(address(vault), bytes32(0), bytes32(uint256(1)));", "cheat-alias"),
    ("IVm x = IVm(address(vm)); x.prank(owner);", "cheat-alias"),
    ("Vm(VM_ADDRESS).mockCall(a, b, c);", "cheat-alias"),
    ("x.etch(target, code);", "code-etch"),
    ("x.prank(owner);", "privileged-prank"),
    ("vm.copyStorage(a, b);", "storage-write"),
    ("vm.setArbitraryStorage(a);", "storage-write"),
])
def test_aliased_cheatcodes_caught(src, rule):
    assert (rule, "high") in rules(src), src
    assert has_blocking(lint_source(src))
