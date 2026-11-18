// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

/// Prefunded native-asset settlement vault for a single local bridge deployment.
contract LocalSettlement {
    address immutable operator;
    bytes32 immutable domain;
    bytes32 immutable asset;
    mapping(bytes32 => bytes32) private receipts;

    event Paid(bytes32 indexed escrow, address indexed recipient, uint128 amount);

    constructor(bytes32 domain_, bytes32 asset_) payable {
        operator = msg.sender;
        domain = domain_;
        asset = asset_;
    }

    function confirmation(bytes32 d, bytes32 a, bytes32 id, address recipient, uint128 amount)
        public view returns (bytes32 receipt)
    {
        require(d == domain && a == asset && recipient != address(0) && amount != 0, "invalid payout");
        receipt = receipts[id];
        require(receipt == 0 || receipt == digest(id, recipient, amount), "conflicting replay");
    }

    function pay(bytes32 d, bytes32 a, bytes32 id, address payable recipient, uint128 amount) external {
        require(msg.sender == operator, "not operator");
        if (confirmation(d, a, id, recipient, amount) != 0) return;
        receipts[id] = digest(id, recipient, amount);
        (bool ok,) = recipient.call{value: amount}("");
        require(ok, "transfer failed");
        emit Paid(id, recipient, amount);
    }

    function digest(bytes32 id, address recipient, uint128 amount) private view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), domain, asset, id, recipient, amount));
    }
}
