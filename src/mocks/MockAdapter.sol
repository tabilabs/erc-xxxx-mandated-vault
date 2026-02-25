// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

/// @title MockAdapter
/// @notice A simple adapter for testing MandatedVault execution.
contract MockAdapter {
    event Executed(address indexed vault, bytes data, uint256 value);

    /// @notice Simply emits an event. Used for basic execution tests.
    function doNothing() external payable {
        emit Executed(msg.sender, msg.data, msg.value);
    }

    /// @notice Transfers ERC-20 tokens from the vault (caller) to a recipient.
    /// @dev The vault must have approved this adapter or hold the tokens directly.
    function transferToken(address token, address to, uint256 amount) external {
        (bool ok, bytes memory ret) = token.call(
            abi.encodeWithSignature("transfer(address,uint256)", to, amount)
        );
        require(ok && (ret.length == 0 || abi.decode(ret, (bool))), "transfer failed");
    }

    /// @notice A function that always reverts, for testing failure paths.
    function alwaysReverts() external pure {
        revert("MockAdapter: forced revert");
    }

    receive() external payable {}
}

/// @title ReentrantAdapter
/// @notice Adapter that attempts to reenter the vault's execute function.
contract ReentrantAdapter {
    address public immutable vault;
    bytes public reentrantCalldata;

    constructor(address vault_) {
        vault = vault_;
    }

    function setReentrantCalldata(bytes calldata data) external {
        reentrantCalldata = data;
    }

    function attack() external {
        (bool ok,) = vault.call(reentrantCalldata);
        // We expect this to fail due to reentrancy guard
        require(ok, "ReentrantAdapter: reentry should have failed");
    }

    /// @notice Replays revert data from the reentrant call for selector-level assertions in tests.
    function attackBubble() external {
        (bool ok, bytes memory ret) = vault.call(reentrantCalldata);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    receive() external payable {}
}

/// @title ShortReturnAuthority
/// @notice ERC-1271 authority that returns less than 32 bytes (invalid response).
contract ShortReturnAuthority {
    /// @dev Matches IERC1271.isValidSignature selector but returns only 4 bytes via assembly.
    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        assembly {
            mstore(0, 0x1626ba7e00000000000000000000000000000000000000000000000000000000)
            return(0, 4) // only 4 bytes, less than required 32
        }
    }
}
