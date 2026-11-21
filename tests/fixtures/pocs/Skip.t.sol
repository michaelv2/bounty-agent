// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface Vm {
    function skip(bool) external;
}

/// Vacuous PoC: skips itself. forge exits 0 for a skipped test; validation must not pass it.
contract SkipPoC {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function test_exploit() public {
        vm.skip(true);
    }
}
