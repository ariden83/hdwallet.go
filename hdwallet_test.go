package hdwallet

import (
	"crypto/ecdsa"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/assert"
)

// Helper function to generate a sample wallet for testing
func createTestWallet(t *testing.T) *Wallet {
	mnemonic, err := NewMnemonic()
	assert.NoError(t, err)

	config := &Config{
		Mnemonic: mnemonic,
		Path:     `m/44'/60'/0'/0/0`,
		Network:  "mainnet",
	}

	wallet, err := New(config)
	assert.NoError(t, err)
	assert.NotNil(t, wallet)

	return wallet
}

func Test_SelectDerivationPath(t *testing.T) {
	tests := []struct {
		network     Network
		path        string
		expected    string
		expectError bool
	}{
		{NetworkMainnet, "", `m/44'/60'/0'/0`, false},
		{NetworkTestnet, "", `m/44'/1'/0'/0`, false},
		{Network("invalid"), "", "", true},
	}

	for _, test := range tests {
		result, err := selectDerivationPath(test.network, test.path)
		if (err != nil) != test.expectError {
			t.Errorf("expected error: %v, got: %v", test.expectError, err)
		}
		if result != test.expected {
			t.Errorf("expected: %s, got: %s", test.expected, result)
		}
	}
}

func Test_SelectNetworkParams(t *testing.T) {
	tests := []struct {
		network     Network
		expectError bool
	}{
		{NetworkMainnet, false},
		{NetworkTestnet, false},
		{Network("invalid"), true},
	}

	for _, test := range tests {
		_, err := selectNetworkParams(test.network)
		if (err != nil) != test.expectError {
			t.Errorf("expected error: %v, got: %v", test.expectError, err)
		}
	}
}

func Test_GenerateMasterKey(t *testing.T) {
	seed := []byte("test seed")
	params := &chaincfg.MainNetParams

	_, err := generateMasterKey(seed, params)
	if err == nil {
		t.Errorf("expected an error, got none")
	}
}

// Test for PrivateKey function.
func Test_PrivateKey(t *testing.T) {
	wallet := createTestWallet(t)

	privateKey := wallet.PrivateKey()
	assert.NotNil(t, privateKey)
	assert.IsType(t, &ecdsa.PrivateKey{}, privateKey)
}

// Test for PrivateKeyBytes function.
func Test_PrivateKeyBytes(t *testing.T) {
	wallet := createTestWallet(t)

	privateKeyBytes := wallet.PrivateKeyBytes()
	assert.NotEmpty(t, privateKeyBytes)
	assert.Len(t, privateKeyBytes, 32) // Ensure private key is 32 bytes long
}

// Test for PrivateKeyHex function.
func Test_PrivateKeyHex(t *testing.T) {
	wallet := createTestWallet(t)

	privateKeyHex := wallet.PrivateKeyHex()
	assert.NotEmpty(t, privateKeyHex)
	assert.Len(t, privateKeyHex, 64) // Hex string should be 64 characters long
}

// Test for PublicKey function.
func Test_PublicKey(t *testing.T) {
	wallet := createTestWallet(t)

	publicKey := wallet.PublicKey()
	assert.NotNil(t, publicKey)
	assert.IsType(t, &ecdsa.PublicKey{}, publicKey)
}

// Test for PublicKeyBytes function.
func Test_PublicKeyBytes(t *testing.T) {
	wallet := createTestWallet(t)

	publicKeyBytes := wallet.PublicKeyBytes()
	assert.NotEmpty(t, publicKeyBytes)
	assert.Len(t, publicKeyBytes, 65) // Public key in uncompressed format should be 65 bytes
}

// Test for PublicKeyHex function.
func Test_PublicKeyHex(t *testing.T) {
	wallet := createTestWallet(t)

	publicKeyHex := wallet.PublicKeyHex()
	assert.NotEmpty(t, publicKeyHex)
	assert.Len(t, publicKeyHex, 128) // Hex string should be 128 characters long (uncompressed public key)
}

// Test for Address function.
func Test_Address(t *testing.T) {
	wallet := createTestWallet(t)

	address := wallet.Address()
	assert.NotNil(t, address)
	assert.Equal(t, 20, len(address.Bytes())) // Ethereum address should be 20 bytes
}

// Test for AddressHex function.
func Test_AddressHex(t *testing.T) {
	wallet := createTestWallet(t)

	addressHex := wallet.AddressHex()
	assert.NotEmpty(t, addressHex)
	assert.Equal(t, 42, len(addressHex)) // Hex string for Ethereum address should be 42 characters long (0x + 40 characters)
}

// Test for Path function.
func Test_Path(t *testing.T) {
	wallet := createTestWallet(t)

	path := wallet.Path()
	assert.NotEmpty(t, path)
	assert.Equal(t, `m/44'/60'/0'/0/0`, path) // Ensure the derivation path is correct
}

// Test for Mnemonic function.
func Test_Mnemonic(t *testing.T) {
	wallet := createTestWallet(t)

	mnemonic := wallet.Mnemonic()
	assert.NotEmpty(t, mnemonic)

	t.Run("empty mnemomic", func(t *testing.T) {
		config := &Config{
			Mnemonic: "",
			Path:     `m/44'/0'/0'/0`,
			Network:  NetworkMainnet,
		}
		wallet, err := New(config)
		assert.EqualError(t, err, ErrInvalidMnemonic)
		assert.Nil(t, wallet)
	})

	t.Run("invalid mnemomic", func(t *testing.T) {
		config := &Config{
			Mnemonic: "invalid invalid invalid invalid invalid",
			Path:     `m/44'/0'/0'/0`,
			Network:  NetworkMainnet,
		}
		wallet, err := New(config)
		assert.EqualError(t, err, ErrInvalidMnemonic)
		assert.Nil(t, wallet)
	})
}

func Test_New_with_mainnet(t *testing.T) {
	mnemonic := "spatial firm squeeze despair sock drink lawn reveal one notice giggle atom"
	root, err := New(&Config{
		Mnemonic: mnemonic,
		Network:  "mainnet",
	})
	if err != nil {
		t.Error(err)
	}

	if root.PrivateKeyHex() != "3df43f760a90d2fd13b396c2ce2824b33d7f9975b52ae4a47ba2cf3f0d60e9b7" {
		t.Error("wrong private key")
	}

	if root.PublicKeyHex() != "d922a563a31b5f28afb569043733b33410388f85f16d2da0c36051ae759b23103b7cdede7517aa1160ea69a6cbf5fdde42c9b50698320016993a10ce9ecf07a3" {
		t.Error("wrong public key")
	}

	if root.AddressHex() != "0x834AE6D77506259AF605B30e4b94863474afd674" {
		t.Error("wrong address")
	}

	if root.Path() != `m/44'/60'/0'/0` {
		t.Error("wrong hdpath")
	}

	wallet, err := root.Derive(0)
	if err != nil {
		t.Error(err)
	}

	if wallet.PrivateKeyHex() != "5c5282b13ddb844fbf408976022d72b154a684685e2ed1e469a264b9c0dd9f69" {
		t.Error("wrong private key")
	}

	if wallet.PublicKeyHex() != "5c30254e5a1916f36210551021cf7216fdf3a5fc8368742b8030ec9cd30bc9eabea6a1085b283e2fa511d1f9be1de1e7137908a64484e805f82404a1ff5ba54e" {
		t.Error("wrong public key")
	}

	if wallet.AddressHex() != "0x603D0D232821F721e142eCf36aFD263183E6daC5" {
		t.Error("wrong address")
	}

	if wallet.Path() != `m/44'/60'/0'/0/0` {
		t.Error("wrong hdpath")
	}
}

func Test_New_with_testnet(t *testing.T) {
	mnemonic := "spatial firm squeeze despair sock drink lawn reveal one notice giggle atom"
	root, err := New(&Config{
		Mnemonic: mnemonic,
		Network:  "testnet",
	})
	if err != nil {
		t.Error(err)
	}

	if root.PrivateKeyHex() != "fcb2eab87e5226dc978b68e375536397450bbaa79362fb12ab45b1411d76473e" {
		t.Error("wrong private key")
	}

	if root.PublicKeyHex() != "e811e21a4ae18ab733c028de62175113076d58edb754281fa34daf142455947403f04fe94e151a7c212fe122ef4846ed364713b87071e6ca49e0c6ea12adc9b6" {
		t.Error("wrong public key")
	}

	if root.AddressHex() != "0x47da7CcBD8d56280dD793FEe254974566b8Ea3D0" {
		t.Error("wrong address")
	}

	if root.Path() != `m/44'/1'/0'/0` {
		t.Error("wrong hdpath")
	}

	wallet, err := root.Derive(0)
	if err != nil {
		t.Error(err)
	}

	if wallet.PrivateKeyHex() != "7d6a87d0c082e2b0c3b091bbceb7a40553532abecbf2f0dbc97da9e473935238" {
		t.Error("wrong private key")
	}

	if wallet.PublicKeyHex() != "b9681c8141f71e01987bc9a21fcb773289c31695e0c671479d9262e08914b01293fe1ee1686941acec99f06e11b6f259ed17b84c4956abaf076a18f704586cee" {
		t.Error("wrong public key")
	}

	if wallet.AddressHex() != "0xBA7FE3C059B3BC7c78674d1F8EDf48AEb828CB35" {
		t.Error("wrong address")
	}

	if wallet.Path() != `m/44'/1'/0'/0/0` {
		t.Error("wrong hdpath")
	}
}
