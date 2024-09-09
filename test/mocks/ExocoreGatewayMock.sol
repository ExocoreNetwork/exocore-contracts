pragma solidity ^0.8.19;

import {IExocoreGateway} from "src/interfaces/IExocoreGateway.sol";

import {IAssets} from "src/interfaces/precompiles/IAssets.sol";
import {IClaimReward} from "src/interfaces/precompiles/IClaimReward.sol";
import {IDelegation} from "src/interfaces/precompiles/IDelegation.sol";

import {
    MessagingFee,
    MessagingReceipt,
    OAppReceiverUpgradeable,
    OAppUpgradeable,
    Origin
} from "src/lzApp/OAppUpgradeable.sol";
import {ExocoreGatewayStorage} from "src/storage/ExocoreGatewayStorage.sol";

import {IOAppCore} from "@layerzero-v2/oapp/contracts/oapp/interfaces/IOAppCore.sol";
import {OptionsBuilder} from "@layerzero-v2/oapp/contracts/oapp/libs/OptionsBuilder.sol";
import {ILayerZeroReceiver} from "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroReceiver.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {Errors} from "src/libraries/Errors.sol";
import {OAppCoreUpgradeable} from "src/lzApp/OAppCoreUpgradeable.sol";

contract ExocoreGatewayMock is
    Initializable,
    PausableUpgradeable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    IExocoreGateway,
    ExocoreGatewayStorage,
    OAppUpgradeable
{

    using OptionsBuilder for bytes;

    address public immutable ASSETS_PRECOMPILE_ADDRESS;
    address public immutable CLAIM_REWARD_PRECOMPILE_ADDRESS;
    address public immutable DELEGATION_PRECOMPILE_ADDRESS;

    IAssets internal immutable ASSETS_CONTRACT;
    IClaimReward internal immutable CLAIM_REWARD_CONTRACT;
    IDelegation internal immutable DELEGATION_CONTRACT;

    modifier onlyCalledFromThis() {
        require(
            msg.sender == address(this),
            "ExocoreGateway: can only be called from this contract itself with a low-level call"
        );
        _;
    }

    constructor(
        address endpoint_,
        address assetsPrecompileMock,
        address ClaimRewardPrecompileMock,
        address delegationPrecompileMock
    ) OAppUpgradeable(endpoint_) {
        require(endpoint_ != address(0), "Endpoint address cannot be zero.");
        require(assetsPrecompileMock != address(0), "Assets precompile address cannot be zero.");
        require(ClaimRewardPrecompileMock != address(0), "ClaimReward precompile address cannot be zero.");
        require(delegationPrecompileMock != address(0), "Delegation precompile address cannot be zero.");

        ASSETS_PRECOMPILE_ADDRESS = assetsPrecompileMock;
        CLAIM_REWARD_PRECOMPILE_ADDRESS = ClaimRewardPrecompileMock;
        DELEGATION_PRECOMPILE_ADDRESS = delegationPrecompileMock;

        ASSETS_CONTRACT = IAssets(ASSETS_PRECOMPILE_ADDRESS);
        CLAIM_REWARD_CONTRACT = IClaimReward(CLAIM_REWARD_PRECOMPILE_ADDRESS);
        DELEGATION_CONTRACT = IDelegation(DELEGATION_PRECOMPILE_ADDRESS);

        _disableInitializers();
    }

    receive() external payable {}

    function initialize(address owner_) external initializer {
        require(owner_ != address(0), "ExocoreGateway: owner can not be zero address");

        _initializeWhitelistFunctionSelectors();
        _transferOwnership(owner_);
        __OAppCore_init_unchained(owner_);
        __Pausable_init_unchained();
    }

    function _initializeWhitelistFunctionSelectors() private {
        _whiteListFunctionSelectors[Action.REQUEST_DEPOSIT] = this.requestDeposit.selector;
        _whiteListFunctionSelectors[Action.REQUEST_DELEGATE_TO] = this.requestDelegateTo.selector;
        _whiteListFunctionSelectors[Action.REQUEST_UNDELEGATE_FROM] = this.requestUndelegateFrom.selector;
        _whiteListFunctionSelectors[Action.REQUEST_WITHDRAW_PRINCIPAL_FROM_EXOCORE] =
            this.requestWithdrawPrincipal.selector;
        _whiteListFunctionSelectors[Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE] = this.requestWithdrawReward.selector;
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    function markBootstrap(uint32 chainIndex) public payable whenNotPaused nonReentrant {
        _markBootstrap(chainIndex);
    }

    function _markBootstrap(uint32 chainIndex) internal {
        // we don't track that a request was sent to a chain to allow for retrials
        // if the transaction fails on the destination chain
        _sendInterchainMsg(chainIndex, Action.REQUEST_MARK_BOOTSTRAP, "", false);
        emit BootstrapRequestSent(chainIndex);
    }

    /**
     * @notice Register the `cientChainId` and othe meta data to Exocore native module or update clien chain's meta data
     * according to the `clinetChainId`.
     * And set trusted remote peer to enable layerzero messaging or other bridge messaging.
     * @param clientChainId The endpoint ID for client chain.
     * @param peer The trusted remote contract address to be associated with the corresponding endpoint or some
     * authorized signer that would be trusted for
     * sending messages from/to source chain to/from this contract
     * @param addressLength The bytes length of address type on that client chain
     * @param name The name of client chain
     * @param metaInfo The arbitrary metadata for client chain
     * @param signatureType The cryptographic signature type that client chain supports
     *
     * @dev Only the owner/admin of the OApp can call this function.
     * @dev Indicates that the peer is trusted to send LayerZero messages to this OApp.
     * @dev Peer is a bytes32 to accommodate non-evm chains.
     */
    function registerOrUpdateClientChain(
        uint32 clientChainId,
        bytes32 peer,
        uint8 addressLength,
        string calldata name,
        string calldata metaInfo,
        string calldata signatureType
    ) public onlyOwner whenNotPaused {
        require(clientChainId != uint32(0), "ExocoreGateway: client chain id cannot be zero or empty");
        require(peer != bytes32(0), "ExocoreGateway: peer address cannot be zero or empty");
        require(addressLength != 0, "ExocoreGateway: address length cannot be zero or empty");
        require(bytes(name).length != 0, "ExocoreGateway: name cannot be empty");
        require(bytes(metaInfo).length != 0, "ExocoreGateway: meta data cannot be empty");
        // signature type could be left as empty for current implementation

        bool updated = _registerOrUpdateClientChain(clientChainId, addressLength, name, metaInfo, signatureType);
        super.setPeer(clientChainId, peer);

        if (updated) {
            emit ClientChainUpdated(clientChainId);
        } else {
            emit ClientChainRegistered(clientChainId);
        }
    }

    function setPeer(uint32 clientChainId, bytes32 clientChainGateway)
        public
        override(IOAppCore, OAppCoreUpgradeable)
        onlyOwner
        whenNotPaused
    {
        _validateClientChainIdRegistered(clientChainId);
        super.setPeer(clientChainId, clientChainGateway);
    }

    function addWhitelistToken(
        uint32 clientChainId,
        bytes32 token,
        uint8 decimals,
        uint256 totalSupply,
        string calldata name,
        string calldata metaData,
        string calldata oracleInfo,
        uint256 tvlLimit
    ) external payable onlyOwner whenNotPaused nonReentrant {
        if (msg.value == 0) {
            revert Errors.ZeroValue();
        }
        require(clientChainId != 0, "ExocoreGateway: client chain id cannot be zero");
        require(token != bytes32(0), "ExocoreGateway: token cannot be zero address");
        require(totalSupply > 0, "ExocoreGateway: total supply should not be zero");
        require(bytes(name).length != 0, "ExocoreGateway: name cannot be empty");
        require(bytes(metaData).length != 0, "ExocoreGateway: meta data cannot be empty");
        require(bytes(oracleInfo).length != 0, "ExocoreGateway: oracleInfo cannot be empty");
        require(totalSupply >= tvlLimit, "ExocoreGateway: total supply should be greater than or equal to TVL limit");
        // setting a tvl limit of 0 is psermitted to add an inactive token, which will be later
        // activated on the client chain

        bool success = ASSETS_CONTRACT.registerToken(
            clientChainId,
            abi.encodePacked(token), // convert to bytes from bytes32
            decimals,
            totalSupply,
            name,
            metaData,
            oracleInfo
        );
        if (success) {
            emit WhitelistTokenAdded(clientChainId, token);
            _sendInterchainMsg(
                clientChainId, Action.REQUEST_ADD_WHITELIST_TOKEN, abi.encodePacked(token, tvlLimit), false
            );
        } else {
            revert AddWhitelistTokenFailed(clientChainId, token);
        }
    }

    function updateWhitelistToken(uint32 clientChainId, bytes32 token, uint256 totalSupply, string calldata metaData)
        external
        payable
        onlyOwner
        whenNotPaused
        nonReentrant
    {
        require(clientChainId != 0, "ExocoreGateway: client chain id cannot be zero");
        require(token != bytes32(0), "ExocoreGateway: token cannot be zero address");
        // it is possible to set total supply to 0 if the tvl limit on the client chain gateway is 0, and if there
        // are no deposits at all.
        // empty metaData indicates that the token's metadata should not be updated
        (bool success, uint256 previousSupply) = ASSETS_CONTRACT.getTotalSupply(clientChainId, abi.encodePacked(token));
        if (!success) {
            // safe to revert since this is not an LZ message so far
            revert FailedToGetTotalSupply(clientChainId, token);
        }
        if (totalSupply >= previousSupply) {
            // supply increase is always permitted without any checks
            if (msg.value > 0) {
                revert Errors.NonZeroValue();
            }
            success = ASSETS_CONTRACT.updateToken(clientChainId, abi.encodePacked(token), totalSupply, metaData);
            if (success) {
                emit WhitelistTokenUpdated(clientChainId, token);
            } else {
                revert UpdateWhitelistTokenFailed(clientChainId, token);
            }
        } else {
            require(bytes(metaData).length == 0, "ExocoreGateway: metadata should be empty for supply decrease");
            // supply decrease is only permitted if tvl limit <= total supply
            supplyDecreasesInFlight[clientChainId][token]++;
            uint64 requestNonce = _sendInterchainMsg(
                clientChainId, Action.REQUEST_VALIDATE_LIMITS, abi.encodePacked(token, totalSupply), false
            );
            // there is only one type of outgoing request for which we expect a response so no need to store
            // too much information
            _registeredRequests[clientChainId][requestNonce] = abi.encode(token, totalSupply);
        }
    }

    /// @inheritdoc IExocoreGateway
    function getTotalSupply(uint32 clientChainId, bytes32 token)
        external
        view
        returns (bool success, uint256 totalSupply)
    {
        return ASSETS_CONTRACT.getTotalSupply(clientChainId, abi.encodePacked(token));
    }

    function _validateClientChainIdRegistered(uint32 clientChainId) internal view {
        (bool success, bool isRegistered) = ASSETS_CONTRACT.isRegisteredClientChain(clientChainId);
        if (!success) {
            revert Errors.ExocoreGatewayFailedToCheckClientChainId();
        }
        if (!isRegistered) {
            revert Errors.ExocoreGatewayNotRegisteredClientChainId();
        }
    }

    function _registerOrUpdateClientChain(
        uint32 clientChainId,
        uint8 addressLength,
        string calldata name,
        string calldata metaInfo,
        string calldata signatureType
    ) internal returns (bool) {
        (bool success, bool updated) =
            ASSETS_CONTRACT.registerOrUpdateClientChain(clientChainId, addressLength, name, metaInfo, signatureType);
        if (!success) {
            revert RegisterClientChainToExocoreFailed(clientChainId);
        }
        return updated;
    }

    function _lzReceive(Origin calldata _origin, bytes calldata payload)
        internal
        virtual
        override
        whenNotPaused
        nonReentrant
    {
        _verifyAndUpdateNonce(_origin.srcEid, _origin.sender, _origin.nonce);

        Action act = Action(uint8(payload[0]));
        if (act == Action.RESPOND) {
            _handleResponse(_origin.srcEid, payload[1:]);
        } else {
            bytes4 selector_ = _whiteListFunctionSelectors[act];
            if (selector_ == bytes4(0)) {
                revert UnsupportedRequest(act);
            }

            (bool success, bytes memory responseOrReason) =
                address(this).call(abi.encodePacked(selector_, abi.encode(_origin.srcEid, _origin.nonce, payload[1:])));
            if (!success) {
                revert RequestExecuteFailed(act, _origin.nonce, responseOrReason);
            }
        }

        emit MessageExecuted(act, _origin.nonce);
    }

    function _handleResponse(uint32 clientChainId, bytes calldata response) internal {
        // only one type of response is supported
        _validatePayloadLength(response, VALIDATE_LIMITS_RESPONSE_LENGTH, Action.RESPOND);
        uint64 lzNonce = uint64(bytes8(response[0:8]));
        (bytes32 token, uint256 totalSupply) =
            abi.decode(_registeredRequests[clientChainId][lzNonce], (bytes32, uint256));
        if (uint8(bytes1(response[8])) == 1) {
            // the validation succeeded, so apply the edit to total supply
            bool updated = ASSETS_CONTRACT.updateToken(clientChainId, abi.encodePacked(token), totalSupply, "");
            if (!updated) {
                emit UpdateWhitelistTokenFailedOnResponse(clientChainId, token);
            } else {
                emit WhitelistTokenUpdated(clientChainId, token);
            }
        } else {
            emit WhitelistTokenNotUpdated(clientChainId, token);
        }
        delete _registeredRequests[clientChainId][lzNonce];
        supplyDecreasesInFlight[clientChainId][token]--;
        return;
    }

    function requestValidateLimits(uint32 srcChainId, uint64 lzNonce, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        _validatePayloadLength(payload, VALIDATE_LIMITS_REQUEST_LENGTH, Action.REQUEST_VALIDATE_LIMITS);

        bytes memory token = payload[:32];
        uint256 tvlLimit = uint256(bytes32(payload[32:64]));

        (bool success, uint256 totalSupply) = ASSETS_CONTRACT.getTotalSupply(srcChainId, token);

        _sendInterchainMsg(
            srcChainId,
            Action.RESPOND,
            abi.encodePacked(
                lzNonce, success && tvlLimit <= totalSupply && supplyDecreasesInFlight[srcChainId][bytes32(token)] == 0
            ),
            true
        );
    }

    function requestDeposit(uint32 srcChainId, uint64 lzNonce, bytes calldata payload) public onlyCalledFromThis {
        _validatePayloadLength(payload, DEPOSIT_REQUEST_LENGTH, Action.REQUEST_DEPOSIT);

        bytes memory token = payload[:32];
        bytes memory depositor = payload[32:64];
        uint256 amount = uint256(bytes32(payload[64:96]));

        (bool success, uint256 updatedBalance) = ASSETS_CONTRACT.depositTo(srcChainId, token, depositor, amount);
        if (!success) {
            revert DepositRequestShouldNotFail(srcChainId, lzNonce);
        }

        _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success, updatedBalance), true);
    }

    function requestWithdrawPrincipal(uint32 srcChainId, uint64 lzNonce, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        _validatePayloadLength(
            payload, WITHDRAW_PRINCIPAL_REQUEST_LENGTH, Action.REQUEST_WITHDRAW_PRINCIPAL_FROM_EXOCORE
        );

        bytes memory token = payload[:32];
        bytes memory withdrawer = payload[32:64];
        uint256 amount = uint256(bytes32(payload[64:96]));

        try ASSETS_CONTRACT.withdrawPrincipal(srcChainId, token, withdrawer, amount) returns (
            bool success, uint256 updatedBalance
        ) {
            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success, updatedBalance), true);
        } catch {
            emit ExocorePrecompileError(ASSETS_PRECOMPILE_ADDRESS, lzNonce);

            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, false, uint256(0)), true);
        }
    }

    function requestWithdrawReward(uint32 srcChainId, uint64 lzNonce, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        _validatePayloadLength(payload, CLAIM_REWARD_REQUEST_LENGTH, Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE);

        bytes memory token = payload[:32];
        bytes memory withdrawer = payload[32:64];
        uint256 amount = uint256(bytes32(payload[64:96]));

        try CLAIM_REWARD_CONTRACT.claimReward(srcChainId, token, withdrawer, amount) returns (
            bool success, uint256 updatedBalance
        ) {
            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success, updatedBalance), true);
        } catch {
            emit ExocorePrecompileError(CLAIM_REWARD_PRECOMPILE_ADDRESS, lzNonce);

            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, false, uint256(0)), true);
        }
    }

    function requestDelegateTo(uint32 srcChainId, uint64 lzNonce, bytes calldata payload) public onlyCalledFromThis {
        _validatePayloadLength(payload, DELEGATE_REQUEST_LENGTH, Action.REQUEST_DELEGATE_TO);

        bytes memory token = payload[:32];
        bytes memory delegator = payload[32:64];
        bytes memory operator = payload[64:106];
        uint256 amount = uint256(bytes32(payload[106:138]));

        try DELEGATION_CONTRACT.delegateToThroughClientChain(srcChainId, lzNonce, token, delegator, operator, amount)
        returns (bool success) {
            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success), true);
        } catch {
            emit ExocorePrecompileError(DELEGATION_PRECOMPILE_ADDRESS, lzNonce);

            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, false), true);
        }
    }

    function requestUndelegateFrom(uint32 srcChainId, uint64 lzNonce, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        _validatePayloadLength(payload, UNDELEGATE_REQUEST_LENGTH, Action.REQUEST_UNDELEGATE_FROM);

        bytes memory token = payload[:32];
        bytes memory delegator = payload[32:64];
        bytes memory operator = payload[64:106];
        uint256 amount = uint256(bytes32(payload[106:138]));

        try DELEGATION_CONTRACT.undelegateFromThroughClientChain(
            srcChainId, lzNonce, token, delegator, operator, amount
        ) returns (bool success) {
            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, success), true);
        } catch {
            emit ExocorePrecompileError(DELEGATION_PRECOMPILE_ADDRESS, lzNonce);

            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, false), true);
        }
    }

    function requestDepositThenDelegateTo(uint32 srcChainId, uint64 lzNonce, bytes calldata payload)
        public
        onlyCalledFromThis
    {
        _validatePayloadLength(payload, DEPOSIT_THEN_DELEGATE_REQUEST_LENGTH, Action.REQUEST_DEPOSIT_THEN_DELEGATE_TO);

        bytes memory token = payload[:32];
        bytes memory depositor = payload[32:64];
        bytes memory operator = payload[64:106];
        uint256 amount = uint256(bytes32(payload[106:138]));

        // while some of the code from requestDeposit and requestDelegateTo is duplicated here,
        // it is done intentionally to work around Solidity's limitations with regards to
        // function calls, error handling and indexing the return data of memory type.
        // for example, you cannot index a bytes memory result from the requestDepositTo call,
        // if you were to modify it to return bytes and then process them here.

        (bool success, uint256 updatedBalance) = ASSETS_CONTRACT.depositTo(srcChainId, token, depositor, amount);
        if (!success) {
            revert DepositRequestShouldNotFail(srcChainId, lzNonce);
        }
        try DELEGATION_CONTRACT.delegateToThroughClientChain(srcChainId, lzNonce, token, depositor, operator, amount)
        returns (bool delegateSuccess) {
            _sendInterchainMsg(
                srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, delegateSuccess, updatedBalance), true
            );
        } catch {
            emit ExocorePrecompileError(DELEGATION_PRECOMPILE_ADDRESS, lzNonce);
            _sendInterchainMsg(srcChainId, Action.RESPOND, abi.encodePacked(lzNonce, false, updatedBalance), true);
        }
    }

    function _validatePayloadLength(bytes calldata payload, uint256 expectedLength, Action action) private pure {
        if (payload.length != expectedLength) {
            revert InvalidRequestLength(action, expectedLength, payload.length);
        }
    }

    function _sendInterchainMsg(uint32 srcChainId, Action act, bytes memory actionArgs, bool payByApp)
        internal
        whenNotPaused
        returns (uint64)
    {
        bytes memory payload = abi.encodePacked(act, actionArgs);
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(
            DESTINATION_GAS_LIMIT, DESTINATION_MSG_VALUE
        ).addExecutorOrderedExecutionOption();
        MessagingFee memory fee = _quote(srcChainId, payload, options, false);

        MessagingReceipt memory receipt =
            _lzSend(srcChainId, payload, options, MessagingFee(fee.nativeFee, 0), msg.sender, payByApp);
        emit MessageSent(act, receipt.guid, receipt.nonce, receipt.fee.nativeFee);

        return receipt.nonce;
    }

    function quote(uint32 srcChainid, bytes memory _message) public view returns (uint256 nativeFee) {
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(
            DESTINATION_GAS_LIMIT, DESTINATION_MSG_VALUE
        ).addExecutorOrderedExecutionOption();
        MessagingFee memory fee = _quote(srcChainid, _message, options, false);
        return fee.nativeFee;
    }

    function nextNonce(uint32 srcEid, bytes32 sender)
        public
        view
        virtual
        override(ILayerZeroReceiver, OAppReceiverUpgradeable)
        returns (uint64)
    {
        return inboundNonce[srcEid][sender] + 1;
    }

}
