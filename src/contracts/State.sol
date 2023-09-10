// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.4;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "./interfaces/IVerifier.sol";
import "./interfaces/IState.sol";

/**
 * @dev Set and get state for each identity
 */
contract State is OwnableUpgradeable, IState {
    /**
     * @dev Struct save for each identity. Stores state and block/timestamp associated.
     */
    struct IDState {
        uint64 BlockN;
        uint64 BlockTimeStamp;
        bytes32 State;
    }

    /**
     * @dev Struct save information about transitions state for identifier.
     * @param replaceAtTimestamp commit time when state was changed.
     * @param createAtTimestamp commit time when state was commit to blockchain.
     * @param replacedAtBlock commit block number when state was changed.
     * @param createdAtBlock commit block number when state was commit to blockchain.
     * @param id identity.
     * @param replaceBy commit state which replaced the current state.
     */
    struct transitionInfo {
        uint256 replaceAtTimestamp;
        uint256 createAtTimestamp;
        uint64 replacedAtBlock;
        uint64 createdAtBlock;
        uint256 id;
        bytes32 replaceBy;
    }

    /**
     * @dev verifier address
     */
    IVerifier public verifier;
    /**
     * @dev Correlation between identity and its state
     */
    mapping(uint256 => IDState[]) public identities;
    /**
     * @dev Correlation between transition info and identity
     */
    mapping(bytes32 => transitionInfo) public transitions;
    /**
     * @param id identity
     * @param blockN block number when state was committed
     * @param timestamp timestamp when state was committed
     * @param state IDState committed
     */
    event StateUpdated(
        uint256 id,
        uint64 blockN,
        uint64 timestamp,
        bytes32 state
    );

    function initialize(IVerifier _verifierContractAddr)
        public
        initializer
    {
        verifier = _verifierContractAddr;
        __Ownable_init();
    }

    function setVerifier(address newVerifier) public onlyOwner {
        verifier = IVerifier(newVerifier);
    }

    function transitState(
        uint256 id,
        bool isOldStateGenesis,
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) public {
        
        require(_publicInputs.length == 2, "public inputs size must be 2");

        bytes32 oldState = _publicInputs[0];
        bytes32 newState = _publicInputs[1];

        if (isOldStateGenesis == false) {
            require(
                identities[id].length > 0,
                "there should be at least one state for identity in smart contract when isOldStateGenesis == 0"
            );

            IDState memory oldIDState = identities[id][
                identities[id].length - 1
            ];
            require(
                oldIDState.BlockN != block.number,
                "no multiple set in the same block"
            );
            require(
                oldIDState.State == oldState,
                "oldState argument should be equal to the latest identity state in smart contract when isOldStateGenesis == 0"
            );
        } else {
            require(
                identities[id].length == 0,
                "There should be no states for identity in smart contract when isOldStateGenesis == 1"
            );
            require(transitions[oldState].id == 0, "oldState should not exist");

            // link genesis state to Id in the smart contract, but creation time and creation block is unknown
            transitions[oldState].id = id;

            // push genesis state to identities as latest state
            identities[id].push(IDState(0, 0, oldState));
        }
        require(transitions[newState].id == 0, "newState should not exist");

        require(
            verifier.verify(_proof, _publicInputs),
            "zero-knowledge proof of state transition is not valid"
        );

        identities[id].push(
            IDState(uint64(block.number), uint64(block.timestamp), newState)
        );

        // Set create info for new state
        transitions[newState] = transitionInfo(
            0,
            block.timestamp,
            0,
            uint64(block.timestamp),
            id,
            0
        );

        // Set replace info for old state
        transitions[oldState].replaceAtTimestamp = block.timestamp;
        transitions[oldState].replacedAtBlock = uint64(block.number);
        transitions[oldState].replaceBy = newState;

        emit StateUpdated(
            id,
            uint64(block.number),
            uint64(block.timestamp),
            newState
        );
    }

    /**
     * Retrieve last state for a given identity
     * @param id identity
     * @return last state committed
     */
    function getState(uint256 id) override public view returns (bytes32) {
        if (identities[id].length == 0) {
            return 0;
        }
        return identities[id][identities[id].length - 1].State;
    }

    /**
     * Retrieve transition information by state
     * @param state is state to check when it lost actuality
     * @return timestamp of new state published after given one
     * @return timestamp of new state published
     * @return block number of new state published after give one
     * @return block number of new state published
     * @return id identity
     * @return the state that replaced the given one
     */
    function getTransitionInfo(bytes32 state)
        override
        public
        view
        returns (
            uint256,
            uint256,
            uint64,
            uint64,
            uint256,
            bytes32
        )
    {
        return (
            transitions[state].replaceAtTimestamp,
            transitions[state].createAtTimestamp,
            transitions[state].replacedAtBlock,
            transitions[state].createdAtBlock,
            transitions[state].id,
            transitions[state].replaceBy
        );
    }

    /**
     * Binary search by block
     * @param id identity
     * @param blockN block number
     * @return block number, block timestamp, state
     */
    function getStateDataByBlock(uint256 id, uint64 blockN)
        public
        view
        returns (
            uint64,
            uint64,
            bytes32
        )
    {
        require(blockN < block.number, "errNoFutureAllowed");
        if (identities[id].length == 0) {
            return (0, 0, 0);
        }

        uint64 lastBlock = identities[id][identities[id].length - 1].BlockN;
        if (blockN > lastBlock) {
            return (
                identities[id][identities[id].length - 1].BlockN,
                identities[id][identities[id].length - 1].BlockTimeStamp,
                identities[id][identities[id].length - 1].State
            );
        }
        // Binary search
        uint256 min = 0;
        uint256 max = identities[id].length - 1;
        while (min <= max) {
            uint256 mid = (max + min) / 2;
            if (identities[id][mid].BlockN == blockN) {
                return (
                    identities[id][mid].BlockN,
                    identities[id][mid].BlockTimeStamp,
                    identities[id][mid].State
                );
            } else if (
                (blockN > identities[id][mid].BlockN) &&
                (blockN < identities[id][mid + 1].BlockN)
            ) {
                return (
                    identities[id][mid].BlockN,
                    identities[id][mid].BlockTimeStamp,
                    identities[id][mid].State
                );
            } else if (blockN > identities[id][mid].BlockN) {
                min = mid + 1;
            } else {
                max = mid - 1;
            }
        }
        return (0, 0, 0);
    }

    /**
     * Binary search by time
     * @param id identity
     * @param timestamp timestamp
     * @return block number, block timestamp, state
     */
    function getStateDataByTime(uint256 id, uint64 timestamp)
        public
        view
        returns (
            uint64,
            uint64,
            bytes32
        )
    {
        require(timestamp < block.timestamp, "errNoFutureAllowed");
        if (identities[id].length == 0) {
            return (0, 0, 0);
        }
        uint64 lastTimestamp = identities[id][identities[id].length - 1]
            .BlockTimeStamp;
        if (timestamp > lastTimestamp) {
            return (
                identities[id][identities[id].length - 1].BlockN,
                identities[id][identities[id].length - 1].BlockTimeStamp,
                identities[id][identities[id].length - 1].State
            );
        }

        //Binary search
        uint256 min = 0;
        uint256 max = identities[id].length - 1;
        while (min <= max) {
            uint256 mid = (max + min) / 2;
            if (identities[id][mid].BlockTimeStamp == timestamp) {
                return (
                    identities[id][mid].BlockN,
                    identities[id][mid].BlockTimeStamp,
                    identities[id][mid].State
                );
            } else if (
                (timestamp > identities[id][mid].BlockTimeStamp) &&
                (timestamp < identities[id][mid + 1].BlockTimeStamp)
            ) {
                return (
                    identities[id][mid].BlockN,
                    identities[id][mid].BlockTimeStamp,
                    identities[id][mid].State
                );
            } else if (timestamp > identities[id][mid].BlockTimeStamp) {
                min = mid + 1;
            } else {
                max = mid - 1;
            }
        }
        return (0, 0, 0);
    }

    /**
     * Retrieve identity last committed information
     * @param id identity
     * @return block number, timestamp, state of the lastest committed state of given identity
     */
    function getStateDataById(uint256 id)
        public
        view
        returns (
            uint64,
            uint64,
            bytes32
        )
    {
        if (identities[id].length == 0) {
            return (0, 0, 0);
        }
        IDState memory lastIdState = identities[id][identities[id].length - 1];
        return (
            lastIdState.BlockN,
            lastIdState.BlockTimeStamp,
            lastIdState.State
        );
    }
}