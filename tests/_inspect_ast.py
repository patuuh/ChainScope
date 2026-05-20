"""Temporary script to inspect tree-sitter Solidity AST node types."""
import tree_sitter_solidity
from tree_sitter import Language, Parser

lang = Language(tree_sitter_solidity.language())
parser = Parser(lang)
code = b'''pragma solidity ^0.8.0;
struct MyStruct { uint x; address owner; }
library SafeMath { function add(uint a, uint b) internal pure returns (uint) { return a + b; } }
interface IVault { function deposit() external payable; }
contract Test {
    uint public balance;
    modifier locked() { require(!_locked); _locked = true; _; _locked = false; }
    bool private _locked;
    function foo() public {
        unchecked { balance += 1; }
        assembly { let x := sload(0) }
        (bool ok,) = msg.sender.call(abi.encode(1));
        (bool ok2,) = address(this).staticcall(abi.encode(0));
        require(tx.origin == msg.sender);
    }
    function bar(uint256[] memory data, bytes calldata input) external pure returns (uint256) { return 0; }
}'''
tree = parser.parse(code)

def pt(node, indent=0):
    line = ' ' * indent + node.type
    if node.child_count == 0:
        line += ' = ' + repr(node.text.decode())
    print(line)
    for child in node.children:
        pt(child, indent + 2)

pt(tree.root_node)
