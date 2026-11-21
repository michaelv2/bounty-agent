// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// Vacuous PoC: contains no test functions. forge exits 0 when zero tests match.
contract NoTestsPoC {
    function helper() public pure returns (uint256) {
        return 1;
    }
}
