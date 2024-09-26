// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.4;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "./interfaces/IValidator.sol";
import "./interfaces/IVerifier.sol";
import "./interfaces/IState.sol";
import "solidity-bytes-utils/contracts/BytesLib.sol";
import "hardhat/console.sol";

contract Query is OwnableUpgradeable, IValidator {

    IVerifier public verifier;
    IState public state;

    uint256 public revocationStateExpirationTime;

    function initialize(
        address _verifierContractAddress,
        address _stateContractAddress
    ) public initializer {
        revocationStateExpirationTime = 1 hours;
        verifier = IVerifier(_verifierContractAddress);
        state = IState(_stateContractAddress);
        __Ownable_init();
    }

    function setRevocationStateExpirationTime(
        uint256 expirationTime
    ) public onlyOwner {
        revocationStateExpirationTime = expirationTime;
    }

    function getValidUntil() public view returns (uint256){
        require(block.timestamp > revocationStateExpirationTime);
        return block.timestamp - revocationStateExpirationTime;
    }

    function verify(
        uint256 holderId,
        uint256 issuerId,
        bytes calldata _proof, 
        bytes32[] calldata _publicInputs
    ) external view override returns (bool r) {
        // verify query
        require(
            getValidUntil() <= uint256(_publicInputs[5]),
            "wrong deterministic value has been used for proof generation"
        );
       
        // verify user state
        
        bytes32 holderState = _publicInputs[0];
        bytes32 issuerClaimIdenState = _publicInputs[2];
        bytes32 issuerClaimNonRevState = _publicInputs[3];

        // 1. User state must be lastest or genesis

        bytes32 userStateFromContract = state.getState(holderId);
        if (userStateFromContract != 0) {
            // The non-empty state is returned, and it’s not equal to the state that the user has provided.
            require(
                userStateFromContract == holderState,
                "User state isn't latest"
            );
        }
       
        // 2. Issuer state must be registered in state contracts or be genesis
        bytes32 issuerStateFromContract = state.getState(issuerId);

        if (issuerStateFromContract != 0) {
            (, , , , uint256 issuerIdFromState, ) = state.getTransitionInfo(
                issuerClaimIdenState
            );
            require(
                issuerId == issuerIdFromState,
                "Issuer state doesn't exist in contract"
            );
            if (issuerStateFromContract != issuerClaimNonRevState) {
                // Non empty state is returned and it's not equal to the state that the user has provided.
                (uint256 replacedAtTimestamp, , , , uint256 id, ) = state
                    .getTransitionInfo(issuerClaimNonRevState);

                if (id == 0 || id != issuerId) {
                    revert("state in transition info contains invalid id");
                }

                if (replacedAtTimestamp == 0) {
                    revert(
                        "Non-latest state doesn't contain replacement information"
                    );
                }

                if (
                    block.timestamp - replacedAtTimestamp >
                    revocationStateExpirationTime
                ) {
                    revert("Issuer non-revocation state expired");
                }
            }
        }
     
   

        require(verifier.verify(_proof, _publicInputs), "MTP not valid");
        return true;
    }
}