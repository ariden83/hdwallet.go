package hdwallet

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	bip32 "github.com/tyler-smith/go-bip32"
	bip39 "github.com/tyler-smith/go-bip39"
)

// Wallet represents an HD wallet.
type Wallet struct {
	mnemonic    string
	path        string
	root        *hdkeychain.ExtendedKey
	extendedKey *hdkeychain.ExtendedKey
	privateKey  *ecdsa.PrivateKey
	publicKey   *ecdsa.PublicKey
}

// Config represents the configuration necessary to create a Wallet.
type Config struct {
	Mnemonic string
	Path     string
	Network  string
}

// New creates a new Wallet from a configuration.
func New(config *Config) (*Wallet, error) {
	var err error

	config.Path, err = selectDerivationPath(config.Network, config.Path)
	if err != nil {
		return nil, err
	}

	if config.Mnemonic == "" {
		return nil, errors.New("mnemonic is required")
	}

	// 1. Selection of network parameters.
	params, err := selectNetworkParams(config.Network)
	if err != nil {
		return nil, err
	}

	// 2. Generate the seed.
	seed := bip39.NewSeed(config.Mnemonic, "")

	// 3. Generate the master key.
	masterKey, err := generateMasterKey(seed, params)
	if err != nil {
		return nil, err
	}

	// 4. Derive key from path.
	key, err := deriveKeyFromPath(masterKey, config.Path)
	if err != nil {
		return nil, err
	}

	// 5. Retrieve private and public keys.
	privateKey, publicKey, err := extractKeys(key)
	if err != nil {
		return nil, err
	}

	// Creation of the portfolio.
	wallet := &Wallet{
		mnemonic:    config.Mnemonic,
		path:        config.Path,
		root:        masterKey,
		extendedKey: key,
		privateKey:  privateKey,
		publicKey:   publicKey,
	}

	return wallet, nil
}

// selectDerivationPath selects the bypass path based on the network.
func selectDerivationPath(network, path string) (string, error) {
	if path == "" {
		switch network {
		case "mainnet":
			return `m/44'/60'/0'/0`, nil
		case "testnet":
			return `m/44'/1'/0'/0`, nil
		default:
			return "", errors.New("unsupported network type: choose either 'mainnet' or 'testnet'")
		}
	}
	return path, nil
}

// selectNetworkParams selects network parameters based on configuration.
func selectNetworkParams(network string) (*chaincfg.Params, error) {
	switch network {
	case "mainnet":
		return &chaincfg.MainNetParams, nil
	case "testnet":
		return &chaincfg.TestNet3Params, nil
	default:
		return nil, errors.New("unsupported network type: choose either 'mainnet' or 'testnet'")
	}
}

// generateMasterKey generates the master key from the seed and network parameters.
func generateMasterKey(seed []byte, params *chaincfg.Params) (*hdkeychain.ExtendedKey, error) {
	masterKey, err := hdkeychain.NewMaster(seed, params)
	if err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}
	return masterKey, nil
}

// deriveKeyFromPath derives a key from the specified derivation path.
func deriveKeyFromPath(masterKey *hdkeychain.ExtendedKey, path string) (*hdkeychain.ExtendedKey, error) {
	dpath, err := accounts.ParseDerivationPath(path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse derivation path: %w", err)
	}

	key := masterKey
	for _, n := range dpath {
		key, err = key.Derive(n)
		if err != nil {
			return nil, fmt.Errorf("failed to derive key: %w", err)
		}
	}
	return key, nil
}

// extractKeys extracts the private and public key from a derived key.
func extractKeys(key *hdkeychain.ExtendedKey) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := key.ECPrivKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get private key: %w", err)
	}
	privateKeyECDSA := privateKey.ToECDSA()

	publicKeyECDSA, ok := privateKeyECDSA.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("failed to get public key")
	}

	return privateKeyECDSA, publicKeyECDSA, nil
}

// Derive derives a new portfolio from an index.
func (s *Wallet) Derive(index interface{}) (*Wallet, error) {
	idx, err := convertToUint32(index)
	if err != nil {
		return nil, err
	}

	// Derive address from index
	derivedKey, err := s.extendedKey.Derive(idx)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Get the ECDSA private key
	privateKey, err := derivedKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}
	privateKeyECDSA := privateKey.ToECDSA()

	// Get the ECDSA public key
	publicKeyECDSA, ok := privateKeyECDSA.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to get public key")
	}

	// Create and return a new derived wallet
	path := fmt.Sprintf("%s/%d", s.path, idx)
	wallet := &Wallet{
		path:        path,
		root:        s.extendedKey,
		extendedKey: derivedKey,
		privateKey:  privateKeyECDSA,
		publicKey:   publicKeyECDSA,
	}
	return wallet, nil
}

// convertToUint32 converts different index types to uint32.
func convertToUint32(index interface{}) (uint32, error) {
	switch v := index.(type) {
	case int:
		if v < 0 {
			return 0, errors.New("index cannot be negative")
		}
		return uint32(v), nil
	case int8, int16, int32:
		if v.(int) < 0 {
			return 0, errors.New("index cannot be negative")
		}
		return uint32(v.(int)), nil
	case int64:
		if v < 0 {
			return 0, errors.New("index cannot be negative")
		}
		return uint32(v), nil
	case uint, uint8, uint16, uint32, uint64:
		return uint32(v.(uint64)), nil
	default:
		return 0, errors.New("unsupported index type")
	}
}

// Utility functions to access Wallet information.

// PrivateKey returns the private key (ECDSA) associated with the wallet.
func (s *Wallet) PrivateKey() *ecdsa.PrivateKey {
	return s.privateKey
}

// PrivateKeyBytes returns the private key in byte format.
func (s *Wallet) PrivateKeyBytes() []byte {
	return crypto.FromECDSA(s.privateKey)
}

// PrivateKeyHex returns the private key in hexadecimal format, removing the "0x" prefix.
func (s *Wallet) PrivateKeyHex() string {
	return hexutil.Encode(s.PrivateKeyBytes())[2:]
}

// PublicKey returns the public key (ECDSA) associated with the wallet.
func (s *Wallet) PublicKey() *ecdsa.PublicKey {
	return s.publicKey
}

// PublicKeyBytes returns the public key in byte format.
func (s *Wallet) PublicKeyBytes() []byte {
	return crypto.FromECDSAPub(s.publicKey)
}

// PublicKeyHex returns the public key in hexadecimal format, removing the "0x" prefix.
func (s *Wallet) PublicKeyHex() string {
	return hexutil.Encode(s.PublicKeyBytes())[4:]
}

// Address returns the Ethereum address derived from the public key.
func (s *Wallet) Address() common.Address {
	return crypto.PubkeyToAddress(*s.publicKey)
}

// AddressHex returns the Ethereum address in hexadecimal format.
func (s *Wallet) AddressHex() string {
	return s.Address().Hex()
}

// Path returns the derivation path used to generate the wallet.
func (s *Wallet) Path() string {
	return s.path
}

// Mnemonic returns the mnemonic phrase used to generate the wallet.
func (s *Wallet) Mnemonic() string {
	return s.mnemonic
}

// Generate a new mnemonic phrase.
func NewMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return "", fmt.Errorf("failed to generate entropy: %w", err)
	}
	return bip39.NewMnemonic(entropy)
}

// NewSeed generates a new BIP32 seed.
func NewSeed() ([]byte, error) {
	return bip32.NewSeed()
}