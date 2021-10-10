package main

import (
    "fmt"
    "log"
    "os"
    "crypto/ecdsa"

    "github.com/ethereum/go-ethereum/common/hexutil"
    "github.com/ethereum/go-ethereum/crypto"
)

func main() {

    args := os.Args[1:]

    if len(args) != 2 {
        fmt.Println("Please provide a hex PK and a message to sign like: \n./signer <pk> <message>")
	os.Exit(1)
    }

    hexPrivateKey := args[0]

    dataToSign := args[1]
    log.Println("Message:", dataToSign)

    privateKey, err := crypto.HexToECDSA(hexPrivateKey[2:])
    if err != nil {
        log.Fatal(err)
    }

    log.Println("Private Key:", hexPrivateKey)

    // keccak256 hash of the data
    dataBytes := []byte(dataToSign)
    log.Println("Message Bytes:", dataBytes)
    hashData := crypto.Keccak256Hash(dataBytes)
    log.Println("Message Hash (keccak256):", hashData)

    // Sign the message hash
    signatureBytes, err := crypto.Sign(hashData.Bytes(), privateKey)
    if err != nil {
        log.Fatal(err)
    }

    // Extract address from private key
    publicKey := privateKey.Public()
    publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
    if !ok {
        log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
    }

    publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
    pubkey := hexutil.Encode(publicKeyBytes)
    log.Println("Public Key:", pubkey)

    // Address of the signer private key
    address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
    log.Println("Address:", address)

    fmt.Println("--------------------------------- RESULTS --------------------------------------")
    fmt.Println("MESSAGE\t\t:", dataToSign)
    fmt.Println("MESSAGE HASH\t:", hashData)
    fmt.Println("ADDRESS\t\t:", address)

    // Signature to hex
    signature := hexutil.Encode(signatureBytes)
    fmt.Println("SIGNATURE\t:", signature)
    fmt.Println("--------------------------------------------------------------------------------")
}

