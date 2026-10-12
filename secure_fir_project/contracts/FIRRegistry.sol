// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract FIRRegistry {
    address public owner;
    struct Record { string firId; string digest; string cid; uint256 timestamp; bool exists; }
    mapping(string => Record) private records;
    event FIRRegistered(string indexed firId,string digest,string cid,uint256 timestamp);
    modifier onlyOwner(){require(msg.sender==owner,"Only owner");_;}
    constructor(){owner=msg.sender;}
    function registerFIR(string calldata firId,string calldata digest,string calldata cid) external onlyOwner {
        require(!records[firId].exists,"Already registered");
        records[firId]=Record(firId,digest,cid,block.timestamp,true);
        emit FIRRegistered(firId,digest,cid,block.timestamp);
    }
    function getFIR(string calldata firId) external view returns(string memory,string memory,string memory,uint256,bool){
        Record memory r=records[firId]; return(r.firId,r.digest,r.cid,r.timestamp,r.exists);
    }
}
