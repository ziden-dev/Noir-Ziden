// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.4;

interface IState {
  function getState(uint id) external view returns (bytes32);
  function getTransitionInfo(bytes32 state)
        external
        view
        returns (
            uint256,
            uint256,
            uint64,
            uint64,
            uint256,
            bytes32
        );
}