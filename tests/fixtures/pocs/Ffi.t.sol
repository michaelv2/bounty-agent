// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface Vm {
    function ffi(string[] calldata) external returns (bytes memory);
}

/// Hostile PoC: tries to run a shell command. The fixture's foundry.toml sets
/// ffi = true, so this only fails if the sandbox overrides the target's config.
contract FfiPoC {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function test_runs_shell() public {
        // Prints "PWN2" only if a shell really runs it (the source text never contains "PWN2").
        string[] memory cmd = new string[](3);
        cmd[0] = "sh";
        cmd[1] = "-c";
        cmd[2] = "echo PWN$((1+1))";
        bytes memory out = vm.ffi(cmd);
        require(out.length == 0, string(out));
    }
}
