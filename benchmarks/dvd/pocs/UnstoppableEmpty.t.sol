// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {UnstoppableChallenge} from "./unstoppable/Unstoppable.t.sol";

/// Negative control: does nothing, so DVD's success check must fail it.
contract BountyPoC is UnstoppableChallenge {
    function test_bounty_solution() public checkSolvedByPlayer {}
}
