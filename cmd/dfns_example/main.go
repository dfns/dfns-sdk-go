package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"

	dfns "github.com/dfns/dfns-sdk-go/v2"
	"github.com/dfns/dfns-sdk-go/v2/wallets"
)

func main() {
	if _, err := os.Stat(".env"); os.IsNotExist(err) {
		log.Println("The .env file does not exist.")
	} else {
		if err := godotenv.Load(".env"); err != nil {
			log.Fatal("Error loading .env file:", err)
		}
	}

	dfnsConfig, err := LoadConfig()
	if err != nil {
		log.Fatal("Error loading config file:", err)
	}

	client, err := dfnsConfig.NewDfnsClient()
	if err != nil {
		log.Fatalln("Error creating Dfns client:", err)
	}

	// Create a wallet
	walletID, err := createWallet(client)
	if err != nil {
		log.Fatalln("Error creating wallet:", err)
	}

	log.Println("Wallet ID:", walletID)

	// Retrieve native balance
	nativeBalance, err := getNativeBalance(client, walletID)
	if err != nil {
		log.Fatalln("Error fetching native balance:", err)
	}

	log.Println("Native Balance:", nativeBalance)
}

func createWallet(client *dfns.Client) (string, error) {
	log.Println("Creating a new wallet")

	wallet, err := client.Wallets.CreateWallet(context.Background(), wallets.CreateWalletRequest{
		Network: "EthereumSepolia",
	})
	if err != nil {
		return "", fmt.Errorf("error creating wallet: %w", err)
	}

	return wallet.ID, nil
}

func getNativeBalance(client *dfns.Client, walletID string) (string, error) {
	log.Println("Retrieving native balance for wallet:", walletID)

	assets, err := client.Wallets.GetWalletAssets(context.Background(), walletID, nil)
	if err != nil {
		return "", fmt.Errorf("error fetching wallet assets: %w", err)
	}

	for _, asset := range assets.Assets {
		kind, _ := asset["kind"].(string)
		if kind == "Native" {
			balance, _ := asset["balance"].(string)
			return balance, nil
		}
	}

	return "", fmt.Errorf("native asset not found")
}
