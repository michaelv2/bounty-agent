// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// A PoC whose claim is false must not pass validation.
contract FailingPoC {
    function test_claims_too_much() public pure {
        require(1 + 1 == 3, "exploit did not work");
    }
}
