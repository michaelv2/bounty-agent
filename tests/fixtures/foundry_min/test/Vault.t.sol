// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Vault} from "../src/Vault.sol";

contract VaultTest {
    function test_deposit_records_balance() public {
        Vault v = new Vault();
        v.deposit{value: 1}();
        require(v.balance(address(this)) == 1, "balance not recorded");
    }

    receive() external payable {}
}
