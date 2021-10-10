pragma solidity >=0.7.0 <0.9.0;

contract TestVerify {
    
  function verify(bytes32 hash, bytes memory sig) public {
      
    bytes32 r;
    bytes32 s;
    uint8 v;

    assembly {
      r := mload(add(sig, 32))
      s := mload(add(sig, 64))
      v := and(mload(add(sig, 65)), 255)
    }

    if (v < 27) {
      v += 27;
    }
    
    address recovered = ecrecover(hash, v, r, s);
    emit LogSignature(hash, sig, recovered);

  }

  event LogSignature (
    bytes32 hash,
    bytes signature,
    address signer
  );
}

