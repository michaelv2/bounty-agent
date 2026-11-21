// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// Minimal fixture: withdraw() forgets to zero the balance, so it can be called twice.
contract Vault {
    mapping(address => uint256) public balance;

    function deposit() external payable { balance[msg.sender] += msg.value; }

    function withdraw() external {
        uint256 amount = balance[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        // BUG: balance[msg.sender] is never set to 0
    }
}
