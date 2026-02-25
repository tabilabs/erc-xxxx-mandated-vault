// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @notice Minimal Uniswap V3 SwapRouter interface (single-hop only).
interface ISwapRouter {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }

    function exactInputSingle(ExactInputSingleParams calldata params) external returns (uint256 amountOut);
}

/// @title UniswapV3SwapAdapter
/// @notice Example adapter demonstrating how a MandatedVault adapter wraps a real DeFi protocol.
///         The vault CALLs this adapter; the adapter forwards the call to Uniswap V3 SwapRouter.
///         This adapter holds no state and no funds between calls.
contract UniswapV3SwapAdapter {
    using SafeERC20 for IERC20;

    ISwapRouter public immutable SWAP_ROUTER;

    constructor(address swapRouter_) {
        SWAP_ROUTER = ISwapRouter(swapRouter_);
    }

    /// @notice Execute a single-hop exact-input swap on Uniswap V3.
    /// @dev The vault must have approved this adapter to spend `amountIn` of `tokenIn`.
    ///      Swapped tokens are sent directly back to `msg.sender` (the vault).
    function swap(address tokenIn, address tokenOut, uint24 fee, uint256 amountIn, uint256 amountOutMinimum)
        external
        returns (uint256 amountOut)
    {
        IERC20(tokenIn).safeTransferFrom(msg.sender, address(this), amountIn);
        IERC20(tokenIn).forceApprove(address(SWAP_ROUTER), amountIn);

        amountOut = SWAP_ROUTER.exactInputSingle(
            ISwapRouter.ExactInputSingleParams({
                tokenIn: tokenIn,
                tokenOut: tokenOut,
                fee: fee,
                recipient: msg.sender, // tokens go back to vault
                amountIn: amountIn,
                amountOutMinimum: amountOutMinimum,
                sqrtPriceLimitX96: 0
            })
        );
    }
}
