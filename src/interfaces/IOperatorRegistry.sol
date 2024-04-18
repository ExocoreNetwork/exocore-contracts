pragma solidity ^0.8.19;

interface IOperatorRegistry {
    /**
     * @dev Represents commission details, represented as 18 decimals.
     * @param rate The current commission rate.
     * @param maxRate The maximum allowable commission rate.
     * @param maxChangeRate The maximum rate at which the commission rate can change.
     * All rates must be less than or equal to 1e18.
     * For example, a 10% commission rate would be represented as 1e17.
     * rate must not exceed maxRate, and maxChangeRate must not exceed maxRate.
    */
    struct Commission {
        uint256 rate;
        uint256 maxRate;
        uint256 maxChangeRate;
    }

    /**
     * @dev Represents an operator in the system, including their registration status,
     * consensus public key for the Exocore chain, commission rate and a unique name.
     *
     * @param name The name (meta info) for the operator.
     * @param commission The commission for the operator.
     * @param consensusPublicKey The public key used by the operator for consensus
     *                           on the Exocore chain.
     */
    struct Operator {
        string name;
        Commission commission;
        bytes32 consensusPublicKey;
    }

    /**
     * @dev Registers a new operator in the registry with the provided details.
     * @param operatorExocoreAddress The Exocore address of the operator as a string.
     * @param name The human-readable name of the operator.
     * @param commission A `Commission` struct containing the commission details for this operator.
     * @param consensusPublicKey The public key used for consensus operations, provided as a bytes32.
     * @notice This function is used to add new operators to the system with their relevant details.
     */
    function registerOperator(
        string calldata operatorExocoreAddress,
        string calldata name,
        Commission memory commission,
        bytes32 consensusPublicKey
    ) external;

    /**
     * @dev Updates the consensus public key for the operator corresponding to `msg.sender`.
     * @param newKey The new public key to use for consensus operations.
     */
    function replaceKey(
        bytes32 newKey
    ) external;

    /**
     * @notice Updates the commission rate for the calling operator.
     * @dev Can only be called by a registered operator. The function checks if the operation
     * is allowed and not paused. Throws if the operator is not registered or the new rate
     * exceeds the maximum allowed rate.
     * @param newRate The new commission rate to be set for the calling operator.
     * Must not exceed the operator's maximum rate.
     */
    function updateRate(
        uint256 newRate
    ) external;

    /**
     * @dev Emitted when a new operator is registered in the contract.
     * @param ethAddress The Ethereum address of the operator.
     * @param operatorExocoreAddress The Exocore address of the operator.
     * @param name The human-readable name of the operator.
     * @param commission The commission details for the operator.
     * @param consensusPublicKey The public key used for consensus operations.
     */
    event OperatorRegistered(
        address ethAddress,
        string operatorExocoreAddress,
        string name,
        IOperatorRegistry.Commission commission,
        bytes32 consensusPublicKey
    );

    /**
     * @dev Emitted when an operator's consensus key is updated.
     * @param operatorExocoreAddress The Exocore address of the operator.
     * @param newConsensusPublicKey The new consensus key for the operator.
     */
    event OperatorKeyReplaced(
        string operatorExocoreAddress,
        bytes32 newConsensusPublicKey
    );

    /**
     * @dev Emitted when an operator's commission rate is updated.
     * @param newRate The new commission rate for the operator.
     */
    event OperatorCommissionUpdated(uint256 newRate);
}