// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.4;

enum QueryType {
    Signle,
    Double,
    Set,
    NonSet
}
interface IValidator{
function verify(
        uint256 holderId,
        uint256 issuerId,
        bytes calldata _proof, 
        bytes32[] calldata _publicInputs
    ) external view returns (bool r);

}