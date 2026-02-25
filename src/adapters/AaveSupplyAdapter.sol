// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @notice Minimal Aave V3 Pool interface (supply/withdraw only).
interface IAavePool {
    function supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;
    function withdraw(address asset, uint256 amount, address to) external returns (uint256);
}

/// @title AaveSupplyAdapter
/// @notice Example adapter demonstrating a multi-function adapter for Aave V3.
///         With the SelectorAllowlist extension, the authority can restrict
///         which functions are callable (e.g., allow supply but not withdraw).
contract AaveSupplyAdapter {
    using SafeERC20 for IERC20;

    IAavePool public immutable POOL;

    constructor(address pool_) {
        POOL = IAavePool(pool_);
    }

    /// @notice Supply assets to Aave V3 on behalf of the vault.
    function supply(address asset, uint256 amount) external {
        IERC20(asset).safeTransferFrom(msg.sender, address(this), amount);
        IERC20(asset).forceApprove(address(POOL), amount);
        POOL.supply(asset, amount, msg.sender, 0);
    }

    /// @notice Withdraw assets from Aave V3 back to the vault.
    function withdraw(address asset, uint256 amount) external returns (uint256) {
        return POOL.withdraw(asset, amount, msg.sender);
    }
}
