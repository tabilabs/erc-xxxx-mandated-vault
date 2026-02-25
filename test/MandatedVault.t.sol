// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {MandatedVault} from "../src/MandatedVault.sol";
import {IERCXXXXMandatedVault} from "../src/interfaces/IERCXXXXMandatedVault.sol";
import {MockAdapter, ReentrantAdapter, ShortReturnAuthority} from "../src/mocks/MockAdapter.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

/// @dev Simple ERC-20 for testing.
contract MockToken is ERC20 {
    constructor() ERC20("Mock Token", "MOCK") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) external {
        _burn(from, amount);
    }
}

/// @dev ERC-1271 contract authority for testing contract-based signatures.
contract MockERC1271Authority is IERC1271 {
    address public signer;

    constructor(address signer_) {
        signer = signer_;
    }

    function isValidSignature(bytes32 hash, bytes memory signature) external view override returns (bytes4) {
        address recovered = ECDSA.recover(hash, signature);
        if (recovered == signer) {
            return 0x1626ba7e;
        }
        return 0xffffffff;
    }
}

/// @dev Adapter that drains tokens from the vault (for drawdown tests).
contract DrainAdapter {
    function drain(address token, address from, uint256 amount) external {
        // Burns tokens from the vault to simulate loss
        (bool ok,) = token.call(abi.encodeWithSignature("burn(address,uint256)", from, amount));
        require(ok, "drain failed");
    }

    receive() external payable {}
}

contract MandatedVaultTest is Test {
    MandatedVault public vault;
    MockToken public token;
    MockAdapter public adapter;

    uint256 internal authorityKey = 0xA11CE;
    address internal authority;
    address internal executor = address(0xE0);

    // Merkle helpers
    bytes32 internal adapterLeaf;
    bytes32 internal merkleRoot;

    function setUp() public {
        authority = vm.addr(authorityKey);

        token = new MockToken();
        vault = new MandatedVault(IERC20(address(token)), "Test Vault", "tVAULT", authority);
        adapter = new MockAdapter();

        // Compute Merkle leaf and root for single adapter
        adapterLeaf = keccak256(abi.encode(address(adapter), address(adapter).codehash));
        merkleRoot = adapterLeaf; // single-leaf tree: root == leaf

        // Fund vault with tokens
        token.mint(address(vault), 1_000_000e18);
    }

    // =========== Helpers ===========

    function _defaultMandate(uint256 nonce) internal view returns (IERCXXXXMandatedVault.Mandate memory) {
        return IERCXXXXMandatedVault.Mandate({
            executor: executor,
            nonce: nonce,
            deadline: 0,
            authorityEpoch: vault.authorityEpoch(),
            maxDrawdownBps: 500, // 5%
            maxCumulativeDrawdownBps: 1000, // 10%
            allowedAdaptersRoot: merkleRoot,
            payloadDigest: bytes32(0),
            extensionsHash: keccak256("")
        });
    }

    function _defaultActions() internal view returns (IERCXXXXMandatedVault.Action[] memory) {
        IERCXXXXMandatedVault.Action[] memory actions = new IERCXXXXMandatedVault.Action[](1);
        actions[0] = IERCXXXXMandatedVault.Action({
            adapter: address(adapter),
            value: 0,
            data: abi.encodeCall(MockAdapter.doNothing, ())
        });
        return actions;
    }

    function _defaultProofs() internal pure returns (bytes32[][] memory) {
        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](0); // single-leaf tree needs no proof
        return proofs;
    }

    function _signMandate(IERCXXXXMandatedVault.Mandate memory mandate) internal view returns (bytes memory) {
        bytes32 mandateHash = vault.hashMandate(mandate);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authorityKey, mandateHash);
        return abi.encodePacked(r, s, v);
    }

    function _executeDefault(uint256 nonce) internal returns (uint256, uint256) {
        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(nonce);
        IERCXXXXMandatedVault.Action[] memory actions = _defaultActions();
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        return vault.execute(mandate, actions, sig, _defaultProofs(), "");
    }

    // =========== Basic Execution ===========

    function test_basicExecution() public {
        (uint256 pre, uint256 post) = _executeDefault(0);
        assertEq(pre, post, "no-op adapter should not change totalAssets");
        assertTrue(vault.isNonceUsed(authority, 0), "nonce should be marked used");
    }

    function test_multipleExecutions() public {
        _executeDefault(0);
        _executeDefault(1);
        _executeDefault(2);
        assertTrue(vault.isNonceUsed(authority, 2));
    }

    // =========== Authority Management ===========

    function test_proposeAndAcceptAuthority() public {
        address newAuth = address(0xBEEF);

        vm.prank(authority);
        vault.proposeAuthority(newAuth);
        assertEq(vault.pendingAuthority(), newAuth);

        vm.prank(newAuth);
        vault.acceptAuthority();
        assertEq(vault.mandateAuthority(), newAuth);
        assertEq(vault.pendingAuthority(), address(0));
    }

    function test_cancelAuthorityTransfer() public {
        address newAuth = address(0xBEEF);

        vm.prank(authority);
        vault.proposeAuthority(newAuth);
        assertEq(vault.pendingAuthority(), newAuth);

        // Cancel by proposing address(0)
        vm.prank(authority);
        vault.proposeAuthority(address(0));
        assertEq(vault.pendingAuthority(), address(0));
    }

    function test_proposeAuthority_revert_notAuthority() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(IERCXXXXMandatedVault.NotAuthority.selector);
        vault.proposeAuthority(address(0xBEEF));
    }

    function test_acceptAuthority_revert_notPending() public {
        vm.prank(authority);
        vault.proposeAuthority(address(0xBEEF));

        vm.prank(address(0xBAD));
        vm.expectRevert(IERCXXXXMandatedVault.NotAuthority.selector);
        vault.acceptAuthority();
    }

    // =========== Revocation ===========

    function test_revokeMandate() public {
        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        bytes32 mandateHash = vault.hashMandate(mandate);

        vm.prank(authority);
        vault.revokeMandate(mandateHash);
        assertTrue(vault.isMandateRevoked(mandateHash));

        // Execution should fail
        bytes memory sig = _signMandate(mandate);
        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.MandateIsRevoked.selector);
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), "");
    }

    function test_invalidateNonce() public {
        vm.prank(authority);
        vault.invalidateNonce(5);
        assertTrue(vault.isNonceUsed(authority, 5));
    }

    function test_invalidateNoncesBelow() public {
        vm.prank(authority);
        vault.invalidateNoncesBelow(10);
        assertEq(vault.nonceThreshold(authority), 10);

        // Mandate with nonce < 10 should fail
        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(5);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.NonceBelowThreshold.selector);
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), "");
    }

    function test_invalidateNoncesBelow_revert_notIncreased() public {
        vm.prank(authority);
        vault.invalidateNoncesBelow(10);

        vm.prank(authority);
        vm.expectRevert(IERCXXXXMandatedVault.ThresholdNotIncreased.selector);
        vault.invalidateNoncesBelow(5);
    }

    // =========== Mandate Validation ===========

    function test_revert_expiredMandate() public {
        vm.warp(1000); // ensure block.timestamp > 1
        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.deadline = uint48(block.timestamp - 1);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.MandateExpired.selector);
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), "");
    }

    function test_revert_wrongExecutor() public {
        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        bytes memory sig = _signMandate(mandate);

        vm.prank(address(0xBAD));
        vm.expectRevert(IERCXXXXMandatedVault.UnauthorizedExecutor.selector);
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), "");
    }

    function test_revert_unboundedOpenMandate() public {
        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.executor = address(0);
        mandate.payloadDigest = bytes32(0);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.UnboundedOpenMandate.selector);
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), "");
    }

    function test_revert_authorityEpochMismatch() public {
        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.authorityEpoch = mandate.authorityEpoch + 1;
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.AuthorityEpochMismatch.selector);
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), "");
    }

    function test_revert_invalidDrawdownBps() public {
        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.maxDrawdownBps = 10_001;
        mandate.maxCumulativeDrawdownBps = 10_001;
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.InvalidDrawdownBps.selector);
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), "");
    }

    function test_revert_invalidCumulativeDrawdownBps() public {
        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.maxDrawdownBps = 500;
        mandate.maxCumulativeDrawdownBps = 100; // less than maxDrawdownBps
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.InvalidCumulativeDrawdownBps.selector);
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), "");
    }

    function test_revert_invalidAdaptersRoot() public {
        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.allowedAdaptersRoot = bytes32(0);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.InvalidAdaptersRoot.selector);
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), "");
    }

    function test_revert_invalidSignature() public {
        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        // Sign with wrong key
        bytes32 mandateHash = vault.hashMandate(mandate);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xDEAD, mandateHash);
        bytes memory badSig = abi.encodePacked(r, s, v);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.InvalidSignature.selector);
        vault.execute(mandate, _defaultActions(), badSig, _defaultProofs(), "");
    }

    function test_revert_nonceReplay() public {
        _executeDefault(0);

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.NonceAlreadyUsed.selector);
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), "");
    }

    function test_revert_emptyActions() public {
        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        IERCXXXXMandatedVault.Action[] memory emptyActions = new IERCXXXXMandatedVault.Action[](0);
        bytes32 digest = keccak256(abi.encode(emptyActions));
        mandate.payloadDigest = digest;
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.EmptyActions.selector);
        vault.execute(mandate, emptyActions, sig, new bytes32[][](0), "");
    }

    function test_revert_payloadDigestMismatch() public {
        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.payloadDigest = bytes32(uint256(1)); // wrong digest
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.PayloadDigestMismatch.selector);
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), "");
    }

    function test_payloadDigestMatch() public {
        IERCXXXXMandatedVault.Action[] memory actions = _defaultActions();
        bytes32 digest = keccak256(abi.encode(actions));

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.payloadDigest = digest;
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vault.execute(mandate, actions, sig, _defaultProofs(), "");
    }

    // =========== Epoch & Circuit Breaker ===========

    function test_epochInitializesOnFirstExecution() public {
        assertEq(vault.epochStart(), 0);
        assertEq(vault.epochAssets(), 0);

        _executeDefault(0);

        assertGt(vault.epochStart(), 0);
        assertEq(vault.epochAssets(), vault.totalAssets());
    }

    function test_resetEpoch() public {
        _executeDefault(0);
        uint48 oldStart = vault.epochStart();

        vm.warp(block.timestamp + 1 days);

        vm.prank(authority);
        vault.resetEpoch();

        assertGt(vault.epochStart(), oldStart);
        assertEq(vault.epochAssets(), vault.totalAssets());
    }

    function test_resetEpoch_revert_notAuthority() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(IERCXXXXMandatedVault.NotAuthority.selector);
        vault.resetEpoch();
    }

    function test_revert_adapterCallFailed() public {
        IERCXXXXMandatedVault.Action[] memory actions = new IERCXXXXMandatedVault.Action[](1);
        actions[0] = IERCXXXXMandatedVault.Action({
            adapter: address(adapter),
            value: 0,
            data: abi.encodeCall(MockAdapter.alwaysReverts, ())
        });

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(); // ActionCallFailed
        vault.execute(mandate, actions, sig, _defaultProofs(), "");
    }

    // =========== ERC-165 ===========

    function test_supportsInterface() public view {
        assertTrue(vault.supportsInterface(type(IERCXXXXMandatedVault).interfaceId));
    }

    function test_interfaceId_constant() public pure {
        assertEq(type(IERCXXXXMandatedVault).interfaceId, bytes4(0x25cb08f6));
    }

    // =========== Constructor ===========

    function test_revert_zeroAddressAuthority() public {
        vm.expectRevert(IERCXXXXMandatedVault.ZeroAddressAuthority.selector);
        new MandatedVault(IERC20(address(token)), "Test", "T", address(0));
    }

    // =========== Open Mandate with Payload ===========

    function test_openMandateWithPayload() public {
        IERCXXXXMandatedVault.Action[] memory actions = _defaultActions();
        bytes32 digest = keccak256(abi.encode(actions));

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.executor = address(0); // open mandate
        mandate.payloadDigest = digest; // bound payload
        bytes memory sig = _signMandate(mandate);

        // Anyone can execute
        vm.prank(address(0x1234));
        vault.execute(mandate, actions, sig, _defaultProofs(), "");
    }

    // =========== NEW: Drawdown & Circuit Breaker ===========

    function test_revert_drawdownExceeded() public {
        DrainAdapter drainer = new DrainAdapter();
        bytes32 drainerLeaf = keccak256(abi.encode(address(drainer), address(drainer).codehash));
        bytes32 drainerRoot = drainerLeaf;

        // Drain 6% (exceeds 5% maxDrawdownBps)
        uint256 drainAmount = 60_000e18; // 6% of 1M
        IERCXXXXMandatedVault.Action[] memory actions = new IERCXXXXMandatedVault.Action[](1);
        actions[0] = IERCXXXXMandatedVault.Action({
            adapter: address(drainer),
            value: 0,
            data: abi.encodeCall(DrainAdapter.drain, (address(token), address(vault), drainAmount))
        });

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.allowedAdaptersRoot = drainerRoot;
        bytes memory sig = _signMandate(mandate);

        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](0);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.DrawdownExceeded.selector);
        vault.execute(mandate, actions, sig, proofs, "");
    }

    function test_cumulativeDrawdownExceeded() public {
        // "Death by a thousand cuts" — multiple small losses each within maxDrawdownBps
        // but cumulative exceeds maxCumulativeDrawdownBps
        DrainAdapter drainer = new DrainAdapter();
        bytes32 drainerLeaf = keccak256(abi.encode(address(drainer), address(drainer).codehash));
        bytes32 drainerRoot = drainerLeaf;

        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](0);

        // Execute 3 times, each draining 4% (within 5% single limit)
        // After 3 executions: cumulative ~11.5% from high-water mark (exceeds 10% cumulative limit)
        for (uint256 i = 0; i < 2; i++) {
            uint256 loopAssets = vault.totalAssets();
            uint256 loopDrainAmount = (loopAssets * 400) / 10_000; // 4%

            IERCXXXXMandatedVault.Action[] memory loopActions = new IERCXXXXMandatedVault.Action[](1);
            loopActions[0] = IERCXXXXMandatedVault.Action({
                adapter: address(drainer),
                value: 0,
                data: abi.encodeCall(DrainAdapter.drain, (address(token), address(vault), loopDrainAmount))
            });

            IERCXXXXMandatedVault.Mandate memory loopMandate = _defaultMandate(i);
            loopMandate.allowedAdaptersRoot = drainerRoot;
            bytes memory loopSig = _signMandate(loopMandate);

            vm.prank(executor);
            vault.execute(loopMandate, loopActions, loopSig, proofs, "");
        }

        // Third execution should trigger cumulative drawdown exceeded
        uint256 currentAssets = vault.totalAssets();
        uint256 drainAmount = (currentAssets * 400) / 10_000; // 4%

        IERCXXXXMandatedVault.Action[] memory actions = new IERCXXXXMandatedVault.Action[](1);
        actions[0] = IERCXXXXMandatedVault.Action({
            adapter: address(drainer),
            value: 0,
            data: abi.encodeCall(DrainAdapter.drain, (address(token), address(vault), drainAmount))
        });

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(2);
        mandate.allowedAdaptersRoot = drainerRoot;
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.CumulativeDrawdownExceeded.selector);
        vault.execute(mandate, actions, sig, proofs, "");
    }

    function test_highWaterMarkUpdate() public {
        // Execute once to initialize epoch
        _executeDefault(0);
        uint256 initialEpochAssets = vault.epochAssets();

        // Simulate profit: mint tokens to vault
        token.mint(address(vault), 100_000e18);

        // Execute again — epochAssets should update to new higher totalAssets
        _executeDefault(1);
        assertGt(vault.epochAssets(), initialEpochAssets, "high-water mark should increase after profit");
        assertEq(vault.epochAssets(), vault.totalAssets(), "epochAssets should equal totalAssets after no-op");
    }

    function test_preAssetsZero_drawdownSkipped() public {
        // Deploy vault with 0 tokens
        MandatedVault emptyVault = new MandatedVault(IERC20(address(token)), "Empty", "eV", authority);

        bytes32 leaf = keccak256(abi.encode(address(adapter), address(adapter).codehash));

        IERCXXXXMandatedVault.Mandate memory mandate = IERCXXXXMandatedVault.Mandate({
            executor: executor,
            nonce: 0,
            deadline: 0,
            authorityEpoch: emptyVault.authorityEpoch(),
            maxDrawdownBps: 0, // strictest possible
            maxCumulativeDrawdownBps: 0,
            allowedAdaptersRoot: leaf,
            payloadDigest: bytes32(0),
            extensionsHash: keccak256("")
        });

        IERCXXXXMandatedVault.Action[] memory actions = new IERCXXXXMandatedVault.Action[](1);
        actions[0] = IERCXXXXMandatedVault.Action({
            adapter: address(adapter),
            value: 0,
            data: abi.encodeCall(MockAdapter.doNothing, ())
        });

        bytes32 mandateHash = emptyVault.hashMandate(mandate);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authorityKey, mandateHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](0);

        vm.prank(executor);
        (uint256 pre, uint256 post) = emptyVault.execute(mandate, actions, sig, proofs, "");
        assertEq(pre, 0, "preAssets should be 0");
        assertEq(post, 0, "postAssets should be 0");
    }

    // =========== NEW: ERC-1271 Contract Authority ===========

    function test_erc1271ContractAuthority() public {
        // Deploy ERC-1271 authority that delegates to authorityKey
        MockERC1271Authority contractAuth = new MockERC1271Authority(authority);

        // Deploy vault with contract authority
        MandatedVault contractVault =
            new MandatedVault(IERC20(address(token)), "Contract Auth Vault", "caV", address(contractAuth));
        token.mint(address(contractVault), 1_000_000e18);

        // Create adapter allowlist for this vault
        bytes32 leaf = keccak256(abi.encode(address(adapter), address(adapter).codehash));

        IERCXXXXMandatedVault.Mandate memory mandate = IERCXXXXMandatedVault.Mandate({
            executor: executor,
            nonce: 0,
            deadline: 0,
            authorityEpoch: contractVault.authorityEpoch(),
            maxDrawdownBps: 500,
            maxCumulativeDrawdownBps: 1000,
            allowedAdaptersRoot: leaf,
            payloadDigest: bytes32(0),
            extensionsHash: keccak256("")
        });

        IERCXXXXMandatedVault.Action[] memory actions = new IERCXXXXMandatedVault.Action[](1);
        actions[0] = IERCXXXXMandatedVault.Action({
            adapter: address(adapter),
            value: 0,
            data: abi.encodeCall(MockAdapter.doNothing, ())
        });

        // Sign with the underlying EOA key — ERC-1271 contract validates it
        bytes32 mandateHash = contractVault.hashMandate(mandate);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authorityKey, mandateHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](0);

        vm.prank(executor);
        contractVault.execute(mandate, actions, sig, proofs, "");
        assertTrue(contractVault.isNonceUsed(address(contractAuth), 0));
    }

    function test_revert_erc1271InvalidSignature() public {
        MockERC1271Authority contractAuth = new MockERC1271Authority(authority);
        MandatedVault contractVault =
            new MandatedVault(IERC20(address(token)), "CA Vault", "caV", address(contractAuth));
        token.mint(address(contractVault), 1_000_000e18);

        bytes32 leaf = keccak256(abi.encode(address(adapter), address(adapter).codehash));

        IERCXXXXMandatedVault.Mandate memory mandate = IERCXXXXMandatedVault.Mandate({
            executor: executor,
            nonce: 0,
            deadline: 0,
            authorityEpoch: contractVault.authorityEpoch(),
            maxDrawdownBps: 500,
            maxCumulativeDrawdownBps: 1000,
            allowedAdaptersRoot: leaf,
            payloadDigest: bytes32(0),
            extensionsHash: keccak256("")
        });

        // Sign with WRONG key
        bytes32 mandateHash = contractVault.hashMandate(mandate);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xDEAD, mandateHash);
        bytes memory badSig = abi.encodePacked(r, s, v);

        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](0);

        IERCXXXXMandatedVault.Action[] memory actions = new IERCXXXXMandatedVault.Action[](1);
        actions[0] = IERCXXXXMandatedVault.Action({
            adapter: address(adapter),
            value: 0,
            data: abi.encodeCall(MockAdapter.doNothing, ())
        });

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.InvalidSignature.selector);
        contractVault.execute(mandate, actions, badSig, proofs, "");
    }

    // =========== NEW: Extensions ===========

    function test_revert_unsupportedRequiredExtension() public {
        IERCXXXXMandatedVault.Extension[] memory exts = new IERCXXXXMandatedVault.Extension[](1);
        exts[0] = IERCXXXXMandatedVault.Extension({id: bytes4(0xdeadbeef), required: true, data: ""});
        bytes memory encodedExts = abi.encode(exts);

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.extensionsHash = keccak256(encodedExts);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(
            abi.encodeWithSelector(IERCXXXXMandatedVault.UnsupportedRequiredExtension.selector, bytes4(0xdeadbeef))
        );
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), encodedExts);
    }

    function test_optionalExtensionIgnored() public {
        IERCXXXXMandatedVault.Extension[] memory exts = new IERCXXXXMandatedVault.Extension[](1);
        exts[0] = IERCXXXXMandatedVault.Extension({id: bytes4(0xdeadbeef), required: false, data: "some data"});
        bytes memory encodedExts = abi.encode(exts);

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.extensionsHash = keccak256(encodedExts);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), encodedExts);
        assertTrue(vault.isNonceUsed(authority, 0));
    }

    function test_revert_invalidExtensionsEncoding() public {
        bytes memory garbage = hex"deadbeef0123";

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.extensionsHash = keccak256(garbage);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.InvalidExtensionsEncoding.selector);
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), garbage);
    }

    function test_revert_extensionsNotCanonical_unsorted() public {
        IERCXXXXMandatedVault.Extension[] memory exts = new IERCXXXXMandatedVault.Extension[](2);
        exts[0] = IERCXXXXMandatedVault.Extension({id: bytes4(0xbbbbbbbb), required: false, data: ""});
        exts[1] = IERCXXXXMandatedVault.Extension({id: bytes4(0xaaaaaaaa), required: false, data: ""});
        bytes memory encodedExts = abi.encode(exts);

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.extensionsHash = keccak256(encodedExts);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.ExtensionsNotCanonical.selector);
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), encodedExts);
    }

    function test_revert_extensionsNotCanonical_duplicateId() public {
        IERCXXXXMandatedVault.Extension[] memory exts = new IERCXXXXMandatedVault.Extension[](2);
        exts[0] = IERCXXXXMandatedVault.Extension({id: bytes4(0xaaaaaaaa), required: false, data: ""});
        exts[1] = IERCXXXXMandatedVault.Extension({id: bytes4(0xaaaaaaaa), required: false, data: hex"01"});
        bytes memory encodedExts = abi.encode(exts);

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.extensionsHash = keccak256(encodedExts);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.ExtensionsNotCanonical.selector);
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), encodedExts);
    }

    // =========== NEW: SelectorAllowlist@v1 Extension ===========

    function test_supportsExtension_selectorAllowlistReturnsTrue() public view {
        bytes4 selectorAllowlistId = bytes4(keccak256("erc-xxxx:selector-allowlist@v1"));
        assertTrue(vault.supportsExtension(selectorAllowlistId));
    }

    function test_selectorAllowlist_allowsSingleAction() public {
        IERCXXXXMandatedVault.Action[] memory actions = _defaultActions();

        bytes4 selectorAllowlistId = bytes4(keccak256("erc-xxxx:selector-allowlist@v1"));
        bytes32 leaf = keccak256(abi.encode(address(adapter), MockAdapter.doNothing.selector));
        bytes32 root = leaf; // single-leaf tree: root == leaf

        bytes32[][] memory selectorProofs = new bytes32[][](1);
        selectorProofs[0] = new bytes32[](0);

        IERCXXXXMandatedVault.Extension[] memory exts = new IERCXXXXMandatedVault.Extension[](1);
        exts[0] = IERCXXXXMandatedVault.Extension({
            id: selectorAllowlistId,
            required: false,
            data: abi.encode(root, selectorProofs)
        });
        bytes memory encodedExts = abi.encode(exts);

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.extensionsHash = keccak256(encodedExts);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vault.execute(mandate, actions, sig, _defaultProofs(), encodedExts);
        assertTrue(vault.isNonceUsed(authority, 0));
    }

    function test_revert_selectorAllowlist_selectorNotAllowed() public {
        IERCXXXXMandatedVault.Action[] memory actions = new IERCXXXXMandatedVault.Action[](1);
        actions[0] = IERCXXXXMandatedVault.Action({
            adapter: address(adapter),
            value: 0,
            data: abi.encodeCall(MockAdapter.alwaysReverts, ())
        });

        bytes4 selectorAllowlistId = bytes4(keccak256("erc-xxxx:selector-allowlist@v1"));
        bytes32 allowedLeaf = keccak256(abi.encode(address(adapter), MockAdapter.doNothing.selector));
        bytes32 root = allowedLeaf;

        bytes32[][] memory selectorProofs = new bytes32[][](1);
        selectorProofs[0] = new bytes32[](0);

        IERCXXXXMandatedVault.Extension[] memory exts = new IERCXXXXMandatedVault.Extension[](1);
        exts[0] = IERCXXXXMandatedVault.Extension({
            id: selectorAllowlistId,
            required: false,
            data: abi.encode(root, selectorProofs)
        });
        bytes memory encodedExts = abi.encode(exts);

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.extensionsHash = keccak256(encodedExts);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(
            abi.encodeWithSelector(
                MandatedVault.SelectorNotAllowed.selector, 0, address(adapter), MockAdapter.alwaysReverts.selector
            )
        );
        vault.execute(mandate, actions, sig, _defaultProofs(), encodedExts);
    }

    function test_revert_selectorAllowlist_invalidActionDataTooShort() public {
        IERCXXXXMandatedVault.Action[] memory actions = new IERCXXXXMandatedVault.Action[](1);
        actions[0] = IERCXXXXMandatedVault.Action({adapter: address(adapter), value: 0, data: hex"010203"});

        bytes4 selectorAllowlistId = bytes4(keccak256("erc-xxxx:selector-allowlist@v1"));
        bytes32 root = bytes32(uint256(123));

        bytes32[][] memory selectorProofs = new bytes32[][](1);
        selectorProofs[0] = new bytes32[](0);

        IERCXXXXMandatedVault.Extension[] memory exts = new IERCXXXXMandatedVault.Extension[](1);
        exts[0] = IERCXXXXMandatedVault.Extension({
            id: selectorAllowlistId,
            required: false,
            data: abi.encode(root, selectorProofs)
        });
        bytes memory encodedExts = abi.encode(exts);

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.extensionsHash = keccak256(encodedExts);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(MandatedVault.InvalidActionData.selector, 0));
        vault.execute(mandate, actions, sig, _defaultProofs(), encodedExts);
    }

    function test_revert_selectorAllowlist_proofLengthMismatch() public {
        IERCXXXXMandatedVault.Action[] memory actions = _defaultActions();

        bytes4 selectorAllowlistId = bytes4(keccak256("erc-xxxx:selector-allowlist@v1"));
        bytes32 root = keccak256(abi.encode(address(adapter), MockAdapter.doNothing.selector));

        // proofs.length != actions.length => InvalidExtensionsEncoding
        bytes32[][] memory selectorProofs = new bytes32[][](0);

        IERCXXXXMandatedVault.Extension[] memory exts = new IERCXXXXMandatedVault.Extension[](1);
        exts[0] = IERCXXXXMandatedVault.Extension({
            id: selectorAllowlistId,
            required: false,
            data: abi.encode(root, selectorProofs)
        });
        bytes memory encodedExts = abi.encode(exts);

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.extensionsHash = keccak256(encodedExts);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.InvalidExtensionsEncoding.selector);
        vault.execute(mandate, actions, sig, _defaultProofs(), encodedExts);
    }

    // =========== NEW: Input Limits (reference implementation) ===========

    function test_revert_tooManyActions() public {
        uint256 n = vault.MAX_ACTIONS() + 1;

        IERCXXXXMandatedVault.Action[] memory actions = new IERCXXXXMandatedVault.Action[](n);
        bytes32[][] memory proofs = new bytes32[][](n);
        for (uint256 i = 0; i < n; i++) {
            actions[i] = IERCXXXXMandatedVault.Action({
                adapter: address(adapter),
                value: 0,
                data: abi.encodeCall(MockAdapter.doNothing, ())
            });
            proofs[i] = new bytes32[](0);
        }

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(MandatedVault.TooManyActions.selector, n));
        vault.execute(mandate, actions, sig, proofs, "");
    }

    function test_revert_extensionsTooLarge() public {
        uint256 n = vault.MAX_EXTENSIONS_BYTES() + 1;
        bytes memory big = new bytes(n);

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(MandatedVault.ExtensionsTooLarge.selector, n));
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), big);
    }

    function test_revert_tooManyExtensions() public {
        uint256 n = vault.MAX_EXTENSIONS() + 1;

        IERCXXXXMandatedVault.Extension[] memory exts = new IERCXXXXMandatedVault.Extension[](n);
        for (uint256 i = 0; i < n; i++) {
            exts[i] = IERCXXXXMandatedVault.Extension({id: bytes4(uint32(i + 1)), required: false, data: ""});
        }
        bytes memory encodedExts = abi.encode(exts);

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.extensionsHash = keccak256(encodedExts);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(MandatedVault.TooManyExtensions.selector, n));
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), encodedExts);
    }

    function test_revert_adapterProofTooDeep() public {
        uint256 depth = vault.MAX_ADAPTER_PROOF_DEPTH() + 1;

        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](depth);
        for (uint256 i = 0; i < depth; i++) {
            proofs[0][i] = bytes32(uint256(i + 1));
        }

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(MandatedVault.AdapterProofTooDeep.selector, 0, depth));
        vault.execute(mandate, _defaultActions(), sig, proofs, "");
    }

    function test_revert_selectorAllowlist_selectorProofTooDeep() public {
        IERCXXXXMandatedVault.Action[] memory actions = _defaultActions();

        bytes4 selectorAllowlistId = bytes4(keccak256("erc-xxxx:selector-allowlist@v1"));
        bytes32 root = keccak256(abi.encode(address(adapter), MockAdapter.doNothing.selector));

        uint256 depth = vault.MAX_SELECTOR_PROOF_DEPTH() + 1;
        bytes32[][] memory selectorProofs = new bytes32[][](1);
        selectorProofs[0] = new bytes32[](depth);
        for (uint256 i = 0; i < depth; i++) {
            selectorProofs[0][i] = bytes32(uint256(i + 1));
        }

        IERCXXXXMandatedVault.Extension[] memory exts = new IERCXXXXMandatedVault.Extension[](1);
        exts[0] = IERCXXXXMandatedVault.Extension({
            id: selectorAllowlistId,
            required: false,
            data: abi.encode(root, selectorProofs)
        });
        bytes memory encodedExts = abi.encode(exts);

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.extensionsHash = keccak256(encodedExts);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(MandatedVault.SelectorProofTooDeep.selector, 0, depth));
        vault.execute(mandate, actions, sig, _defaultProofs(), encodedExts);
    }

    // =========== NEW: Multi-Adapter Merkle ===========

    function test_multiAdapterMerkleProof() public {
        MockAdapter adapter2 = new MockAdapter();

        bytes32 leaf1 = keccak256(abi.encode(address(adapter), address(adapter).codehash));
        bytes32 leaf2 = keccak256(abi.encode(address(adapter2), address(adapter2).codehash));

        // Sorted pair Merkle root (OpenZeppelin convention)
        bytes32 root;
        if (leaf1 < leaf2) {
            root = keccak256(abi.encodePacked(leaf1, leaf2));
        } else {
            root = keccak256(abi.encodePacked(leaf2, leaf1));
        }

        IERCXXXXMandatedVault.Action[] memory actions = new IERCXXXXMandatedVault.Action[](2);
        actions[0] = IERCXXXXMandatedVault.Action({
            adapter: address(adapter),
            value: 0,
            data: abi.encodeCall(MockAdapter.doNothing, ())
        });
        actions[1] = IERCXXXXMandatedVault.Action({
            adapter: address(adapter2),
            value: 0,
            data: abi.encodeCall(MockAdapter.doNothing, ())
        });

        // Proofs: each leaf's proof is the other leaf
        bytes32[][] memory proofs = new bytes32[][](2);
        proofs[0] = new bytes32[](1);
        proofs[0][0] = leaf2;
        proofs[1] = new bytes32[](1);
        proofs[1][0] = leaf1;

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.allowedAdaptersRoot = root;
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vault.execute(mandate, actions, sig, proofs, "");
        assertTrue(vault.isNonceUsed(authority, 0));
    }

    // =========== NEW: Reentrancy ===========

    function test_revert_reentrancy() public {
        ReentrantAdapter reentrant = new ReentrantAdapter(address(vault));

        bytes32 leaf = keccak256(abi.encode(address(reentrant), address(reentrant).codehash));
        bytes32 root = leaf;

        IERCXXXXMandatedVault.Action[] memory actions = new IERCXXXXMandatedVault.Action[](1);
        actions[0] = IERCXXXXMandatedVault.Action({
            adapter: address(reentrant),
            value: 0,
            data: abi.encodeCall(ReentrantAdapter.attack, ())
        });

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.allowedAdaptersRoot = root;
        bytes memory sig = _signMandate(mandate);

        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](0);

        // Set up reentrant calldata (try to call execute again)
        IERCXXXXMandatedVault.Mandate memory mandate2 = _defaultMandate(1);
        mandate2.allowedAdaptersRoot = root;
        bytes memory sig2 = _signMandate(mandate2);

        bytes memory reentrantCalldata = abi.encodeCall(vault.execute, (mandate2, actions, sig2, proofs, ""));
        reentrant.setReentrantCalldata(reentrantCalldata);

        vm.prank(executor);
        vm.expectRevert(); // ReentrancyGuardReentrantCall or ReentrantAdapter require failure
        vault.execute(mandate, actions, sig, proofs, "");
    }

    function test_revert_reentrancyShareMutation() public {
        ReentrantAdapter reentrant = new ReentrantAdapter(address(vault));

        bytes32 leaf = keccak256(abi.encode(address(reentrant), address(reentrant).codehash));
        bytes32 root = leaf;

        IERCXXXXMandatedVault.Action[] memory actions = new IERCXXXXMandatedVault.Action[](1);
        actions[0] = IERCXXXXMandatedVault.Action({
            adapter: address(reentrant),
            value: 0,
            data: abi.encodeCall(ReentrantAdapter.attackBubble, ())
        });

        // Prepare reentrant deposit from adapter address.
        token.mint(address(reentrant), 10e18);
        vm.prank(address(reentrant));
        token.approve(address(vault), type(uint256).max);

        bytes memory reentrantCalldata = abi.encodeCall(vault.deposit, (1e18, address(reentrant)));
        reentrant.setReentrantCalldata(reentrantCalldata);

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.allowedAdaptersRoot = root;
        bytes memory sig = _signMandate(mandate);

        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](0);

        vm.prank(executor);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERCXXXXMandatedVault.ActionCallFailed.selector,
                uint256(0),
                abi.encodeWithSelector(IERCXXXXMandatedVault.VaultBusy.selector)
            )
        );
        vault.execute(mandate, actions, sig, proofs, "");
    }

    // =========== NEW: Utility Functions ===========

    function test_hashActions() public view {
        IERCXXXXMandatedVault.Action[] memory actions = _defaultActions();
        bytes32 expected = keccak256(abi.encode(actions));
        assertEq(vault.hashActions(actions), expected);
    }

    function test_supportsExtension_returnsFalse() public view {
        assertFalse(vault.supportsExtension(bytes4(0xdeadbeef)));
        assertFalse(vault.supportsExtension(bytes4(0x12345678)));
    }

    // =========== NEW R5: Cumulative Drawdown Within Bounds ===========

    function test_cumulativeDrawdownWithinBounds() public {
        // Two small losses (each 3%), cumulative 5.9% — within 10% limit
        DrainAdapter drainer = new DrainAdapter();
        bytes32 drainerLeaf = keccak256(abi.encode(address(drainer), address(drainer).codehash));
        bytes32 drainerRoot = drainerLeaf;

        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](0);

        for (uint256 i = 0; i < 2; i++) {
            uint256 currentAssets = vault.totalAssets();
            uint256 drainAmount = (currentAssets * 300) / 10_000; // 3%

            IERCXXXXMandatedVault.Action[] memory actions = new IERCXXXXMandatedVault.Action[](1);
            actions[0] = IERCXXXXMandatedVault.Action({
                adapter: address(drainer),
                value: 0,
                data: abi.encodeCall(DrainAdapter.drain, (address(token), address(vault), drainAmount))
            });

            IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(i);
            mandate.allowedAdaptersRoot = drainerRoot;
            bytes memory sig = _signMandate(mandate);

            vm.prank(executor);
            vault.execute(mandate, actions, sig, proofs, "");
        }

        // Both executions should succeed — cumulative ~5.9% < 10%
        assertTrue(vault.isNonceUsed(authority, 0));
        assertTrue(vault.isNonceUsed(authority, 1));
    }

    // =========== NEW R5: ERC-1271 Short Return ===========

    function test_revert_erc1271ShortReturn() public {
        ShortReturnAuthority shortAuth = new ShortReturnAuthority();
        MandatedVault shortVault = new MandatedVault(IERC20(address(token)), "Short Auth", "sV", address(shortAuth));
        token.mint(address(shortVault), 1_000_000e18);

        bytes32 leaf = keccak256(abi.encode(address(adapter), address(adapter).codehash));

        IERCXXXXMandatedVault.Mandate memory mandate = IERCXXXXMandatedVault.Mandate({
            executor: executor,
            nonce: 0,
            deadline: 0,
            authorityEpoch: shortVault.authorityEpoch(),
            maxDrawdownBps: 500,
            maxCumulativeDrawdownBps: 1000,
            allowedAdaptersRoot: leaf,
            payloadDigest: bytes32(0),
            extensionsHash: keccak256("")
        });

        IERCXXXXMandatedVault.Action[] memory actions = new IERCXXXXMandatedVault.Action[](1);
        actions[0] = IERCXXXXMandatedVault.Action({
            adapter: address(adapter),
            value: 0,
            data: abi.encodeCall(MockAdapter.doNothing, ())
        });

        bytes32 mandateHash = shortVault.hashMandate(mandate);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authorityKey, mandateHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](0);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.InvalidSignature.selector);
        shortVault.execute(mandate, actions, sig, proofs, "");
    }

    // =========== NEW R5: Proof Length Mismatch ===========

    function test_revert_proofLengthMismatch() public {
        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        IERCXXXXMandatedVault.Action[] memory actions = _defaultActions();
        bytes memory sig = _signMandate(mandate);

        // Provide 0 proofs for 1 action
        bytes32[][] memory emptyProofs = new bytes32[][](0);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.AdapterNotAllowed.selector);
        vault.execute(mandate, actions, sig, emptyProofs, "");
    }

    // =========== NEW R5: EOA Adapter Rejection ===========

    function test_revert_eoaAdapter() public {
        address eoaAdapter = address(0xDEAD);
        // eoaAdapter has no code — should be rejected

        bytes32 leaf = keccak256(abi.encode(eoaAdapter, eoaAdapter.codehash));
        bytes32 root = leaf;

        IERCXXXXMandatedVault.Action[] memory actions = new IERCXXXXMandatedVault.Action[](1);
        actions[0] = IERCXXXXMandatedVault.Action({adapter: eoaAdapter, value: 0, data: ""});

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.allowedAdaptersRoot = root;
        bytes memory sig = _signMandate(mandate);

        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](0);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.AdapterNotAllowed.selector);
        vault.execute(mandate, actions, sig, proofs, "");
    }

    // =========== NEW R5: Codehash Pinning ===========

    function test_codehashPinning() public {
        // Step 1: Execute successfully with current adapter
        _executeDefault(0);
        assertTrue(vault.isNonceUsed(authority, 0));

        // Step 2: Change adapter bytecode via vm.etch
        // The old Merkle root is based on the old codehash
        bytes32 oldCodehash = address(adapter).codehash;

        // Etch new bytecode (different from original)
        vm.etch(address(adapter), hex"6080604052");
        bytes32 newCodehash = address(adapter).codehash;
        assertTrue(oldCodehash != newCodehash, "codehash should change after etch");

        // Step 3: Try to execute with old Merkle root — should fail
        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(1);
        // mandate.allowedAdaptersRoot is still merkleRoot (based on old codehash)
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.AdapterNotAllowed.selector);
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), "");
    }

    // =========== NEW R6: Zero Drawdown Boundary ===========

    function test_revert_zeroDrawdownBoundary() public {
        // maxDrawdownBps=0 means ANY loss (even 1 wei) should revert
        DrainAdapter drainer = new DrainAdapter();
        bytes32 drainerLeaf = keccak256(abi.encode(address(drainer), address(drainer).codehash));
        bytes32 drainerRoot = drainerLeaf;

        // Drain just 1 wei
        IERCXXXXMandatedVault.Action[] memory actions = new IERCXXXXMandatedVault.Action[](1);
        actions[0] = IERCXXXXMandatedVault.Action({
            adapter: address(drainer),
            value: 0,
            data: abi.encodeCall(DrainAdapter.drain, (address(token), address(vault), 1))
        });

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.maxDrawdownBps = 0;
        mandate.maxCumulativeDrawdownBps = 0;
        mandate.allowedAdaptersRoot = drainerRoot;
        bytes memory sig = _signMandate(mandate);

        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = new bytes32[](0);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.DrawdownExceeded.selector);
        vault.execute(mandate, actions, sig, proofs, "");
    }

    // =========== NEW R6: Authority Transfer Invalidates Old Signatures ===========

    function test_authorityTransferInvalidatesOldSignatures() public {
        // Sign a mandate with the current authority
        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        bytes memory sig = _signMandate(mandate);

        // Transfer authority to a new address
        address newAuth = address(0xBEEF);
        vm.prank(authority);
        vault.proposeAuthority(newAuth);
        vm.prank(newAuth);
        vault.acceptAuthority();
        assertEq(vault.mandateAuthority(), newAuth);

        // Old signature should now be invalid due to authorityEpoch mismatch
        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.AuthorityEpochMismatch.selector);
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), "");
    }

    // =========== NEW R6: InvalidateNonce Then Execute ===========

    function test_invalidateNonceThenExecuteReverts() public {
        // Invalidate nonce 0 directly
        vm.prank(authority);
        vault.invalidateNonce(0);
        assertTrue(vault.isNonceUsed(authority, 0));

        // Try to execute with that nonce — should revert
        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.NonceAlreadyUsed.selector);
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), "");
    }

    // =========== NEW R7: Action with ETH Value ===========

    function test_revert_actionWithEthValue() public {
        // Fund vault with ETH
        vm.deal(address(vault), 1 ether);

        // adapter.doNothing() is payable — send 0.5 ETH
        IERCXXXXMandatedVault.Action[] memory actions = new IERCXXXXMandatedVault.Action[](1);
        actions[0] = IERCXXXXMandatedVault.Action({
            adapter: address(adapter),
            value: 0.5 ether,
            data: abi.encodeCall(MockAdapter.doNothing, ())
        });

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.NonZeroActionValue.selector);
        vault.execute(mandate, actions, sig, _defaultProofs(), "");
    }

    // =========== NEW R7: Deadline Boundary (block.timestamp == deadline) ===========

    function test_deadlineExactBoundaryPasses() public {
        vm.warp(1000);
        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.deadline = uint48(block.timestamp); // exactly equal
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        // Should succeed: block.timestamp <= deadline
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), "");
        assertTrue(vault.isNonceUsed(authority, 0));
    }

    // =========== NEW R9: Multi-Action Partial Failure ===========

    function test_revert_multiActionPartialFailure() public {
        // action[0] succeeds (doNothing), action[1] fails (alwaysReverts)
        // Entire transaction must revert, rolling back action[0]'s effects
        IERCXXXXMandatedVault.Action[] memory actions = new IERCXXXXMandatedVault.Action[](2);
        actions[0] = IERCXXXXMandatedVault.Action({
            adapter: address(adapter),
            value: 0,
            data: abi.encodeCall(MockAdapter.doNothing, ())
        });
        actions[1] = IERCXXXXMandatedVault.Action({
            adapter: address(adapter),
            value: 0,
            data: abi.encodeCall(MockAdapter.alwaysReverts, ())
        });

        // Need 2 proofs for 2 actions (same adapter, same proof)
        bytes32[][] memory proofs = new bytes32[][](2);
        proofs[0] = new bytes32[](0);
        proofs[1] = new bytes32[](0);

        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(); // ActionCallFailed for index 1
        vault.execute(mandate, actions, sig, proofs, "");

        // Nonce should NOT be consumed (entire tx reverted)
        assertFalse(vault.isNonceUsed(authority, 0), "nonce must not be used after revert");
    }

    // =========== NEW R9: InvalidCumulativeDrawdownBps > 10_000 ===========

    function test_revert_cumulativeDrawdownBpsExceeds10000() public {
        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        mandate.maxDrawdownBps = 10_000; // valid (exactly 10_000)
        mandate.maxCumulativeDrawdownBps = 10_001; // invalid (> 10_000)
        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.InvalidCumulativeDrawdownBps.selector);
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), "");
    }

    // =========== NEW R8: ExtensionsHashMismatch ===========

    function test_revert_extensionsHashMismatch() public {
        IERCXXXXMandatedVault.Mandate memory mandate = _defaultMandate(0);
        // mandate.extensionsHash = keccak256("") by default

        // Pass non-empty extensions that DON'T match the mandate's extensionsHash
        IERCXXXXMandatedVault.Extension[] memory exts = new IERCXXXXMandatedVault.Extension[](1);
        exts[0] = IERCXXXXMandatedVault.Extension({id: bytes4(0x12345678), required: false, data: ""});
        bytes memory encodedExts = abi.encode(exts);
        // keccak256(encodedExts) != mandate.extensionsHash (which is keccak256(""))

        bytes memory sig = _signMandate(mandate);

        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.ExtensionsHashMismatch.selector);
        vault.execute(mandate, _defaultActions(), sig, _defaultProofs(), encodedExts);
    }

    // =========== NEW: sweepNative (Operational) ===========

    function test_sweepNative_success() public {
        vm.deal(address(vault), 1 ether);
        address payable recipient = payable(address(0xBEEF));

        uint256 beforeVault = address(vault).balance;
        uint256 beforeRecipient = recipient.balance;

        vm.prank(authority);
        vault.sweepNative(recipient, 0.4 ether);

        assertEq(address(vault).balance, beforeVault - 0.4 ether);
        assertEq(recipient.balance, beforeRecipient + 0.4 ether);
    }

    function test_revert_sweepNative_notAuthority() public {
        vm.prank(executor);
        vm.expectRevert(IERCXXXXMandatedVault.NotAuthority.selector);
        vault.sweepNative(payable(address(0xBEEF)), 1);
    }

    function test_revert_sweepNative_zeroAddressRecipient() public {
        vm.deal(address(vault), 1 ether);

        vm.prank(authority);
        vm.expectRevert(MandatedVault.ZeroAddressRecipient.selector);
        vault.sweepNative(payable(address(0)), 1);
    }

    function test_revert_sweepNative_insufficientBalance() public {
        vm.deal(address(vault), 0);

        vm.prank(authority);
        vm.expectRevert(MandatedVault.NativeSweepFailed.selector);
        vault.sweepNative(payable(address(0xBEEF)), 1);
    }
}
