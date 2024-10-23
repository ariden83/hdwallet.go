# HD Wallet Library

This is a Go-based library that provides functionalities to create and manage hierarchical deterministic (HD) wallets. It supports both Bitcoin (mainnet and testnet) and Ethereum wallets, and allows the derivation of private keys, public keys, and addresses.

## Features

- Generate HD wallets using BIP32 and BIP39 standards.
- Support for multiple blockchain networks: Bitcoin (mainnet, testnet) and Ethereum.
- Derivation of keys and addresses based on the provided mnemonic and derivation path.
- Utility functions to return the private key, public key, and address in various formats.
- Validates the mnemonic according to the BIP39 standard.

## Installation

To use this library, you can import it into your Go project. Make sure you have Go modules enabled.

```bash
go get github.com/ariden83/hdwallet.go
```

Then, import it in your Go code:

```go
import "github.com/ariden83/hdwallet.go"
```

## Usage

### Creating a Wallet

To create a new wallet, you need to provide a mnemonic phrase and the derivation path. 

Here's an example of how to create a wallet for the Ethereum mainnet:

```go
wallet := &hdwallet.Config{
    Mnemonic: "your mnemonic phrase here",
    Path:     "m/44'/60'/0'/0", // Derivation path for Ethereum
    Network:  hdwallet.NetworkMainnet,
}

root, err := hdwallet.New(config)
if err != nil {
    log.Fatal(err)
}
```

### Deriving Keys

To derive keys from a wallet, you can use the `Derive` function:

```go
derivedWallet, err := wallet.Derive(0)
if err != nil {
    log.Fatal(err)
}
```

### Getting Public Key and Address

You can get the public key and the address (in `Ethereum format`) as follows:

```go
publicKey := wallet.PublicKeyHex()
address := wallet.AddressHex()

fmt.Println("Public Key:", publicKey)
fmt.Println("Address:", address)
```

### Validating a Bitcoin Address

The library can validate a Bitcoin address based on the network type (`mainnet` or `testnet`).

### Fetching Private Key

To retrieve the private key of the wallet, you can use the following method:

```go
privateKey := wallet.PrivateKeyHex()
fmt.Println("Private Key:", privateKey)
```

## Configuration
The Config struct allows you to specify the following fields when creating a wallet:

- `Mnemonic`: The mnemonic phrase (required).
- `Path`: The derivation path (optional). If not provided, default paths for mainnet/testnet will be used.
- `Network`: Specifies the network (Bitcoin mainnet/testnet or Ethereum).


### Example:

```go
config := &hdwallet.Config{
    Mnemonic: "mnemonic phrase here",
    Path:     "m/44'/60'/0'/0", // Ethereum path
    Network:  hdwallet.NetworkMainnet,
}
```

## Errors
The library defines several error messages for common issues, including:

- `ErrInvalidMnemonic`: If the mnemonic phrase is missing or invalid.
- `ErrUnsupportedNet`: If an unsupported network type is provided.
- `ErrInvalidPath`: If the derivation path cannot be parsed.
- `ErrKeyDerivation`: If key derivation fails.

## Resources

- Fork from [HD Wallet of miguelmota](https://gist.github.com/miguelmota/ee0fd9756e1651f38f4cd38c6e99b8bf)

## Contributing

If you'd like to contribute to this project, feel free to submit a pull request or open an issue on GitHub.

## License

This project is licensed under the MIT License.

