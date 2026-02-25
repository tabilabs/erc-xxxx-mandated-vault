// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MandatedVault} from "../src/MandatedVault.sol";

contract DeployMandatedVault is Script {
    function run() external {
        address asset = vm.envAddress("ASSET_ADDRESS");
        address authority = vm.envAddress("AUTHORITY_ADDRESS");
        string memory name = vm.envOr("VAULT_NAME", string("Mandated Vault"));
        string memory symbol = vm.envOr("VAULT_SYMBOL", string("mVAULT"));

        vm.startBroadcast();

        MandatedVault vault = new MandatedVault(
            IERC20(asset),
            name,
            symbol,
            authority
        );

        console.log("MandatedVault deployed at:", address(vault));
        console.log("Authority:", authority);
        console.log("Asset:", asset);

        vm.stopBroadcast();
    }
}
