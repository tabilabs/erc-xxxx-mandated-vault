// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @title IERCXXXXMandatedVault
/// @notice Minimal interface for risk-constrained delegated strategy execution on ERC-4626 vaults.
interface IERCXXXXMandatedVault /* is IERC4626, IERC165 */ {

    // --------- Structs ---------

    struct Action {
        address adapter;
        uint256 value;
        bytes data;
    }

    struct Mandate {
        address executor;
        uint256 nonce;
        uint48 deadline;
        uint64 authorityEpoch;
        uint16 maxDrawdownBps;
        uint16 maxCumulativeDrawdownBps;
        bytes32 allowedAdaptersRoot;
        bytes32 payloadDigest;
        bytes32 extensionsHash;
    }

    struct Extension {
        bytes4 id;
        bool required;
        bytes data;
    }

    // --------- Events ---------

    event MandateExecuted(
        bytes32 indexed mandateHash,
        address indexed authority,
        address indexed executor,
        bytes32 actionsDigest,
        uint256 preAssets,
        uint256 postAssets
    );

    event MandateRevoked(bytes32 indexed mandateHash, address indexed authority);
    event NonceInvalidated(address indexed authority, uint256 indexed nonce);
    event NoncesInvalidatedBelow(address indexed authority, uint256 threshold);
    event AuthorityTransferred(address indexed previousAuthority, address indexed newAuthority);
    event AuthorityProposed(address indexed currentAuthority, address indexed proposedAuthority);
    event EpochReset(address indexed authority, uint256 newEpochAssets, uint48 newEpochStart);

    // --------- Errors ---------

    error NotAuthority();
    error UnauthorizedExecutor();
    error MandateExpired();
    error AuthorityEpochMismatch();
    error InvalidSignature();
    error NonceAlreadyUsed();
    error NonceBelowThreshold();
    error ThresholdNotIncreased();
    error MandateIsRevoked();
    error ExtensionsHashMismatch();
    error PayloadDigestMismatch();
    error AdapterNotAllowed();
    error UnsupportedRequiredExtension(bytes4 id);
    error InvalidDrawdownBps();
    error InvalidCumulativeDrawdownBps();
    error InvalidAdaptersRoot();
    error DrawdownExceeded();
    error CumulativeDrawdownExceeded();
    error UnboundedOpenMandate();
    error EmptyActions();
    error NonZeroActionValue();
    error ActionCallFailed(uint256 index, bytes reason);
    error ZeroAddressAuthority();
    error InvalidExtensionsEncoding();
    error ExtensionsNotCanonical();
    error VaultBusy();

    // --------- Views ---------

    function mandateAuthority() external view returns (address);
    function authorityEpoch() external view returns (uint64);
    function isNonceUsed(address authority, uint256 nonce) external view returns (bool);
    function isMandateRevoked(bytes32 mandateHash) external view returns (bool);
    function nonceThreshold(address authority) external view returns (uint256);
    function hashMandate(Mandate calldata mandate) external view returns (bytes32);
    function hashActions(Action[] calldata actions) external pure returns (bytes32);
    function epochStart() external view returns (uint48);
    function epochAssets() external view returns (uint256);
    function supportsExtension(bytes4 id) external view returns (bool);

    // --------- Authority management ---------

    function pendingAuthority() external view returns (address);
    function proposeAuthority(address newAuthority) external;
    function acceptAuthority() external;

    // --------- Epoch management ---------

    function resetEpoch() external;

    // --------- Revocation ---------

    function revokeMandate(bytes32 mandateHash) external;
    function invalidateNonce(uint256 nonce) external;
    function invalidateNoncesBelow(uint256 threshold) external;

    // --------- Execution ---------

    function execute(
        Mandate calldata mandate,
        Action[] calldata actions,
        bytes calldata signature,
        bytes32[][] calldata adapterProofs,
        bytes calldata extensions
    ) external returns (uint256 preAssets, uint256 postAssets);
}
