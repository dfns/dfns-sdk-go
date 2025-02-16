package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/dfns/dfns-sdk-go/credentials"
	"github.com/dfns/dfns-sdk-go/dfnsapiclient"
	"github.com/joho/godotenv"
)

type Wallet struct {
	Address     string     `json:"address"`
	Custodial   bool       `json:"custodial"`
	DateCreated string     `json:"dateCreated"`
	ID          string     `json:"id"`
	Network     string     `json:"network"`
	SigningKey  SigningKey `json:"signingKey"`
	Status      string     `json:"status"`
	Tags        []string   `json:"tags"`
}

type SigningKey struct {
	Curve     string `json:"curve"`
	PublicKey string `json:"publicKey"`
	Scheme    string `json:"scheme"`
}

type AssetsResponse struct {
	Assets   []Asset `json:"assets"`
	Network  string  `json:"network"`
	WalletID string  `json:"walletId"`
}

type Asset struct {
	Balance  string `json:"balance"`
	Decimals int    `json:"decimals"`
	Kind     string `json:"kind"`
	Symbol   string `json:"symbol"`
}

func main() {
	// Load environment variables from .env file
	if _, err := os.Stat(".env"); os.IsNotExist(err) {
		log.Println("The .env file does not exist.")
	} else {
		// Load environment variables from .env file
		if err := godotenv.Load(".env"); err != nil {
			log.Fatal("Error loading .env file:", err)
		}
	}

	dfnsConfig, err := LoadConfig()
	if err != nil {
		log.Fatal("Error loading config file:", err)
	}

	apiConfig := dfnsConfig.GetDfnsAPIConfig()

	keySignerConfig, err := dfnsConfig.GetKeySignerConfig()
	if err != nil {
		log.Fatalln("Error getting KeySignerConfig:", err)
	}

	signer := credentials.NewAsymmetricKeySigner(keySignerConfig)

	apiOptions, err := dfnsapiclient.NewDfnsAPIOptions(
		apiConfig,
		signer,
	)
	if err != nil {
		log.Fatalln("Error creating DfnsBaseApiOption:", err)
	}

	httpClient := dfnsapiclient.CreateDfnsAPIClient(apiOptions)

	// Create a wallet
	walletID, err := createWallet(httpClient, apiOptions)
	if err != nil {
		log.Fatalln("Error creating wallet:", err)
	}

	log.Println("Wallet ID:", walletID)

	// Retrieve native balance
	nativeBalance, err := getNativeBalance(httpClient, apiOptions, walletID)
	if err != nil {
		log.Fatalln("Error fetching native balance:", err)
	}

	log.Println("Native Balance:", nativeBalance)
}

// getNativeBalance fetches wallet data from the DFNS API.
func getNativeBalance(client *http.Client, apiOptions *dfnsapiclient.DfnsAPIOptions, walletID string) (string, error) {
	log.Println("Retrieving native balance for wallet:", walletID)

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/wallets/%s/assets", apiOptions.BaseURL, walletID), http.NoBody)
	if err != nil {
		return "", fmt.Errorf("error creating GET request: %w", err)
	}

	response, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error fetching native balance: %w", err)
	}
	defer response.Body.Close()

	var assetsResp AssetsResponse
	if err := json.NewDecoder(response.Body).Decode(&assetsResp); err != nil {
		return "", fmt.Errorf("error decoding assets response: %w", err)
	}

	for _, asset := range assetsResp.Assets {
		if asset.Kind == "Native" {
			return asset.Balance, nil
		}
	}

	return "", fmt.Errorf("native asset not found")
}

// createWallet creates a new wallet via the DFNS API.
func createWallet(client *http.Client, apiOptions *dfnsapiclient.DfnsAPIOptions) (string, error) {
	log.Println("Creating a new wallet")

	walletData := struct {
		Network string `json:"network"`
	}{
		Network: "EthereumGoerli",
	}

	jsonData, err := json.Marshal(walletData)
	if err != nil {
		return "", fmt.Errorf("error marshaling JSON: %w", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/wallets", apiOptions.BaseURL), bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("error creating POST request: %w", err)
	}

	response, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error creating wallet: %w", err)
	}
	defer response.Body.Close()

	var wallet Wallet
	if err := json.NewDecoder(response.Body).Decode(&wallet); err != nil {
		return "", fmt.Errorf("error decoding create wallet response: %w", err)
	}

	return wallet.ID, nil
}
