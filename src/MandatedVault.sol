// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {ERC4626} from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

import {IERCXXXXMandatedVault} from "./interfaces/IERCXXXXMandatedVault.sol";

contract MandatedVault is ERC4626, ERC165, EIP712, ReentrancyGuard, IERCXXXXMandatedVault {

    bytes4 internal constant _ERC1271_MAGICVALUE = 0x1626ba7e;
    bytes32 internal constant _EMPTY_CODEHASH = keccak256("");
    bytes4 internal constant _SELECTOR_ALLOWLIST_ID = bytes4(keccak256("erc-xxxx:selector-allowlist@v1"));
    bytes32 internal constant _MANDATE_TYPEHASH =
        keccak256(
            "Mandate(address executor,uint256 nonce,uint48 deadline,uint64 authorityEpoch,uint16 maxDrawdownBps,uint16 maxCumulativeDrawdownBps,bytes32 allowedAdaptersRoot,bytes32 payloadDigest,bytes32 extensionsHash)"
        );

    // --------- Recommended input limits (DoS/gas grief mitigation) ---------
    // These limits are not part of Core semantics, but are included in the reference implementation
    // to make extreme inputs fail fast and predictably.
    uint256 public constant MAX_ACTIONS = 32;
    uint256 public constant MAX_EXTENSIONS = 16;
    uint256 public constant MAX_ADAPTER_PROOF_DEPTH = 64;
    uint256 public constant MAX_SELECTOR_PROOF_DEPTH = 64;
    uint256 public constant MAX_EXTENSIONS_BYTES = 131_072; // 128 KiB

    event NativeSwept(address indexed to, uint256 amount);

    error InvalidActionData(uint256 index);
    error SelectorNotAllowed(uint256 index, address adapter, bytes4 selector);
    error NativeSweepFailed();
    error ZeroAddressRecipient();
    error TooManyActions(uint256 count);
    error TooManyExtensions(uint256 count);
    error ExtensionsTooLarge(uint256 length);
    error AdapterProofTooDeep(uint256 index, uint256 depth);
    error SelectorProofTooDeep(uint256 index, uint256 depth);

    address private _authority;
    address private _pendingAuthority;
    uint64 private _authorityEpoch;

    mapping(address => mapping(uint256 => bool)) private _nonceUsed;
    mapping(address => uint256) private _nonceThreshold;
    mapping(bytes32 => bool) private _mandateRevoked;

    uint48 private _epochStart;
    uint256 private _epochAssets;

    constructor(IERC20 asset_, string memory name_, string memory symbol_, address authority_)
        ERC20(name_, symbol_)
        ERC4626(asset_)
        EIP712("MandatedExecution", "1")
    {
        if (authority_ == address(0)) revert ZeroAddressAuthority();
        _authority = authority_;
    }

    // --------- Views ---------

    function mandateAuthority() public view returns (address) {
        return _authority;
    }

    function authorityEpoch() external view returns (uint64) {
        return _authorityEpoch;
    }

    function pendingAuthority() external view returns (address) {
        return _pendingAuthority;
    }

    function isNonceUsed(address authority, uint256 nonce) external view returns (bool) {
        return _nonceUsed[authority][nonce];
    }

    function nonceThreshold(address authority) external view returns (uint256) {
        return _nonceThreshold[authority];
    }

    function isMandateRevoked(bytes32 mandateHash) external view returns (bool) {
        return _mandateRevoked[mandateHash];
    }

    function epochStart() external view returns (uint48) {
        return _epochStart;
    }

    function epochAssets() external view returns (uint256) {
        return _epochAssets;
    }

    function supportsExtension(bytes4 id) public view returns (bool) {
        return _supportsExtension(id);
    }

    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(IERCXXXXMandatedVault).interfaceId
            || interfaceId == type(IERC4626).interfaceId
            || super.supportsInterface(interfaceId);
    }

    function hashActions(Action[] calldata actions) external pure returns (bytes32) {
        return keccak256(abi.encode(actions));
    }

    function hashMandate(Mandate calldata mandate) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                _MANDATE_TYPEHASH,
                mandate.executor,
                mandate.nonce,
                mandate.deadline,
                mandate.authorityEpoch,
                mandate.maxDrawdownBps,
                mandate.maxCumulativeDrawdownBps,
                mandate.allowedAdaptersRoot,
                mandate.payloadDigest,
                mandate.extensionsHash
            )
        );
        return _hashTypedDataV4(structHash);
    }

    // --------- Authority management (2-step) ---------

    function proposeAuthority(address newAuthority) external {
        if (msg.sender != _authority) revert NotAuthority();
        _pendingAuthority = newAuthority;
        emit AuthorityProposed(_authority, newAuthority);
    }

    function acceptAuthority() external {
        if (msg.sender != _pendingAuthority) revert NotAuthority();
        address prev = _authority;
        _authority = _pendingAuthority;
        _pendingAuthority = address(0);
        unchecked {
            _authorityEpoch++;
        }
        emit AuthorityTransferred(prev, _authority);
    }

    // --------- Epoch management ---------

    function resetEpoch() external {
        if (msg.sender != _authority) revert NotAuthority();
        _epochAssets = totalAssets();
        _epochStart = uint48(block.timestamp);
        emit EpochReset(_authority, _epochAssets, _epochStart);
    }

    // --------- Revocation ---------

    function invalidateNonce(uint256 nonce) external {
        if (msg.sender != _authority) revert NotAuthority();
        _nonceUsed[_authority][nonce] = true;
        emit NonceInvalidated(_authority, nonce);
    }

    function invalidateNoncesBelow(uint256 threshold) external {
        if (msg.sender != _authority) revert NotAuthority();
        if (threshold <= _nonceThreshold[_authority]) revert ThresholdNotIncreased();
        _nonceThreshold[_authority] = threshold;
        emit NoncesInvalidatedBelow(_authority, threshold);
    }

    function revokeMandate(bytes32 mandateHash) external {
        if (msg.sender != _authority) revert NotAuthority();
        _mandateRevoked[mandateHash] = true;
        emit MandateRevoked(mandateHash, _authority);
    }

    // --------- Execution ---------

    function execute(
        Mandate calldata mandate,
        Action[] calldata actions,
        bytes calldata signature,
        bytes32[][] calldata adapterProofs,
        bytes calldata extensions
    ) external nonReentrant returns (uint256 preAssets, uint256 postAssets) {
        // 1. Validate mandate expiry
        if (mandate.deadline != 0 && block.timestamp > mandate.deadline) revert MandateExpired();

        // 2. Validate executor restriction
        if (mandate.executor != address(0) && msg.sender != mandate.executor) revert UnauthorizedExecutor();

        // 3. Validate open mandate safety (spec step 3)
        if (mandate.executor == address(0) && mandate.payloadDigest == bytes32(0)) {
            revert UnboundedOpenMandate();
        }

        // 4. Validate authority epoch (spec step 4)
        if (mandate.authorityEpoch != _authorityEpoch) revert AuthorityEpochMismatch();

        // 5. Validate mandate constraints
        if (mandate.maxDrawdownBps > 10_000) revert InvalidDrawdownBps();
        if (mandate.maxCumulativeDrawdownBps > 10_000 || mandate.maxCumulativeDrawdownBps < mandate.maxDrawdownBps) {
            revert InvalidCumulativeDrawdownBps();
        }
        if (mandate.allowedAdaptersRoot == bytes32(0)) revert InvalidAdaptersRoot();

        // 5a. Input size limits (reference implementation; includes spec step 11: EmptyActions)
        uint256 actionsLen = actions.length;
        if (actionsLen == 0) revert EmptyActions();
        if (actionsLen > MAX_ACTIONS) revert TooManyActions(actionsLen);
        if (adapterProofs.length != actionsLen) revert AdapterNotAllowed();
        if (extensions.length > MAX_EXTENSIONS_BYTES) revert ExtensionsTooLarge(extensions.length);

        // 6. Validate extensions hash (spec step 6)
        if (keccak256(extensions) != mandate.extensionsHash) revert ExtensionsHashMismatch();

        // 6a. Decode extensions (spec step 6 continued)
        bool hasSelectorAllowlist;
        bytes32 selectorRoot;
        bytes32[][] memory selectorProofs;
        if (extensions.length != 0) {
            try this.decodeExtensions(extensions) returns (Extension[] memory exts) {
                if (exts.length > MAX_EXTENSIONS) revert TooManyExtensions(exts.length);
                for (uint256 i = 1; i < exts.length;) {
                    if (exts[i - 1].id >= exts[i].id) {
                        revert ExtensionsNotCanonical();
                    }
                    unchecked {
                        ++i;
                    }
                }
                for (uint256 i = 0; i < exts.length;) {
                    if (exts[i].required && !_supportsExtension(exts[i].id)) {
                        revert UnsupportedRequiredExtension(exts[i].id);
                    }
                    if (exts[i].id == _SELECTOR_ALLOWLIST_ID) {
                        hasSelectorAllowlist = true;
                        try this.decodeSelectorAllowlist(exts[i].data) returns (bytes32 root, bytes32[][] memory proofs) {
                            selectorRoot = root;
                            selectorProofs = proofs;
                        } catch {
                            revert InvalidExtensionsEncoding();
                        }
                    }
                    unchecked {
                        ++i;
                    }
                }
            } catch {
                revert InvalidExtensionsEncoding();
            }
        }

        // 7. Compute mandate hash & check revocation (spec step 7)
        bytes32 mandateHash_ = hashMandate(mandate);
        if (_mandateRevoked[mandateHash_]) revert MandateIsRevoked();

        // 8. Validate authority signature (spec step 8)
        address authority_ = _authority;
        _verifyAuthoritySig(authority_, mandateHash_, signature);

        // 9. Replay protection (spec step 9)
        if (mandate.nonce < _nonceThreshold[authority_]) revert NonceBelowThreshold();
        if (_nonceUsed[authority_][mandate.nonce]) revert NonceAlreadyUsed();
        _nonceUsed[authority_][mandate.nonce] = true;

        // 10. Optional payload binding (spec step 10)
        bytes32 actionsDigest = keccak256(abi.encode(actions));
        if (mandate.payloadDigest != bytes32(0) && mandate.payloadDigest != actionsDigest) {
            revert PayloadDigestMismatch();
        }

        // 12. Adapter allowlist checks (spec step 12)
        for (uint256 i = 0; i < actionsLen;) {
            address adapter = actions[i].adapter;
            bytes32 codeHash = adapter.codehash;
            // Reject EOAs / precompiles / non-existent accounts (empty code).
            if (codeHash == bytes32(0) || codeHash == _EMPTY_CODEHASH) revert AdapterNotAllowed();
            if (actions[i].value != 0) revert NonZeroActionValue();
            if (adapterProofs[i].length > MAX_ADAPTER_PROOF_DEPTH) {
                revert AdapterProofTooDeep(i, adapterProofs[i].length);
            }

            bytes32 leaf = keccak256(abi.encode(adapter, codeHash));
            if (!MerkleProof.verifyCalldata(adapterProofs[i], mandate.allowedAdaptersRoot, leaf)) {
                revert AdapterNotAllowed();
            }
            unchecked {
                ++i;
            }
        }

        // 12a. Selector allowlist checks (optional extension)
        if (hasSelectorAllowlist) {
            _enforceSelectorAllowlist(actions, selectorRoot, selectorProofs);
        }

        // 13. Pre-state snapshot & epoch initialization (spec step 13)
        preAssets = totalAssets();

        if (_epochStart == 0) {
            _epochStart = uint48(block.timestamp);
            _epochAssets = preAssets;
        }

        // 14. Execute actions (spec step 14)
        for (uint256 i = 0; i < actionsLen;) {
            (bool ok,) = actions[i].adapter.call{value: actions[i].value}(actions[i].data);
            if (!ok) {
                revert ActionCallFailed(i, _copyReturnData());
            }
            unchecked {
                ++i;
            }
        }

        // 15. Post-state snapshot (spec step 15)
        postAssets = totalAssets();

        // 16. Circuit breaker (spec step 16)

        // Single-execution drawdown check
        if (preAssets != 0 && preAssets > postAssets) {
            uint256 loss = preAssets - postAssets;
            if (loss * 10_000 > preAssets * uint256(mandate.maxDrawdownBps)) revert DrawdownExceeded();
        }

        // Cumulative drawdown check (epoch-based high-water mark)
        uint256 eAssets = _epochAssets;
        if (eAssets != 0 && eAssets > postAssets) {
            uint256 cumulativeLoss = eAssets - postAssets;
            if (cumulativeLoss * 10_000 > eAssets * uint256(mandate.maxCumulativeDrawdownBps)) {
                revert CumulativeDrawdownExceeded();
            }
        }

        // High-water mark update
        if (postAssets > eAssets) {
            _epochAssets = postAssets;
        }

        // 17. Emit events (spec step 17)
        emit MandateExecuted(mandateHash_, authority_, msg.sender, actionsDigest, preAssets, postAssets);
    }

    // --------- Internal ---------

    function _supportsExtension(bytes4 id) internal view virtual returns (bool) {
        return id == _SELECTOR_ALLOWLIST_ID;
    }

    /// @dev External helper for try/catch decoding of extensions.
    function decodeExtensions(bytes calldata extensions) external pure returns (Extension[] memory) {
        return abi.decode(extensions, (Extension[]));
    }

    /// @dev External helper for try/catch decoding of selector allowlist extension data.
    function decodeSelectorAllowlist(bytes calldata data) external pure returns (bytes32 root, bytes32[][] memory proofs) {
        (root, proofs) = abi.decode(data, (bytes32, bytes32[][]));
    }

    function _enforceSelectorAllowlist(Action[] calldata actions, bytes32 root, bytes32[][] memory proofs) internal pure {
        if (proofs.length != actions.length) revert InvalidExtensionsEncoding();
        for (uint256 i = 0; i < actions.length;) {
            if (proofs[i].length > MAX_SELECTOR_PROOF_DEPTH) {
                revert SelectorProofTooDeep(i, proofs[i].length);
            }
            bytes calldata callData = actions[i].data;
            if (callData.length < 4) revert InvalidActionData(i);
            bytes4 selector;
            assembly ("memory-safe") {
                selector := calldataload(callData.offset)
            }
            bytes32 leaf = keccak256(abi.encode(actions[i].adapter, selector));
            if (!MerkleProof.verify(proofs[i], root, leaf)) {
                revert SelectorNotAllowed(i, actions[i].adapter, selector);
            }
            unchecked {
                ++i;
            }
        }
    }

    function _copyReturnData() internal pure returns (bytes memory ret) {
        assembly ("memory-safe") {
            let size := returndatasize()
            ret := mload(0x40)
            mstore(ret, size)
            let dst := add(ret, 0x20)
            returndatacopy(dst, 0, size)
            mstore(0x40, add(dst, and(add(size, 0x1f), not(0x1f))))
        }
    }

    function _verifyAuthoritySig(address authority_, bytes32 digest, bytes calldata signature) internal view {
        if (authority_.code.length == 0) {
            (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecoverCalldata(digest, signature);
            if (err != ECDSA.RecoverError.NoError || signer != authority_) revert InvalidSignature();
            return;
        }

        bytes4 magic = _ERC1271_MAGICVALUE;
        uint256 length = signature.length;
        bool ok;

        assembly ("memory-safe") {
            // Encoded calldata is:
            // [ 0x00 - 0x03 ] <selector>
            // [ 0x04 - 0x23 ] <hash>
            // [ 0x24 - 0x43 ] <signature offset> (0x40)
            // [ 0x44 - 0x63 ] <signature length>
            // [ 0x64 - ...  ] <signature data>
            let ptr := mload(0x40)
            mstore(ptr, magic)
            mstore(add(ptr, 0x04), digest)
            mstore(add(ptr, 0x24), 0x40)
            mstore(add(ptr, 0x44), length)
            calldatacopy(add(ptr, 0x64), signature.offset, length)

            // Write only the first 32 bytes of returndata to 0x00.
            ok := staticcall(gas(), authority_, ptr, add(length, 0x64), 0x00, 0x20)
            ok := and(ok, and(gt(returndatasize(), 0x1f), eq(mload(0x00), magic)))
        }

        if (!ok) revert InvalidSignature();
    }

    receive() external payable {}

    function deposit(uint256 assets, address receiver) public override returns (uint256) {
        if (_reentrancyGuardEntered()) revert VaultBusy();
        return super.deposit(assets, receiver);
    }

    function mint(uint256 shares, address receiver) public override returns (uint256) {
        if (_reentrancyGuardEntered()) revert VaultBusy();
        return super.mint(shares, receiver);
    }

    function withdraw(uint256 assets, address receiver, address owner) public override returns (uint256) {
        if (_reentrancyGuardEntered()) revert VaultBusy();
        return super.withdraw(assets, receiver, owner);
    }

    function redeem(uint256 shares, address receiver, address owner) public override returns (uint256) {
        if (_reentrancyGuardEntered()) revert VaultBusy();
        return super.redeem(shares, receiver, owner);
    }

    /// @notice Authority-only escape hatch for native ETH accidentally/forcibly sent to the vault.
    function sweepNative(address payable to, uint256 amount) external {
        if (msg.sender != _authority) revert NotAuthority();
        if (to == address(0)) revert ZeroAddressRecipient();
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert NativeSweepFailed();
        emit NativeSwept(to, amount);
    }
}
