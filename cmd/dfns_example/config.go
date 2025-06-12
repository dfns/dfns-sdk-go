package main

import (
	"crypto"
	"fmt"
	"strings"

	"github.com/spf13/viper"

	"github.com/dfns/dfns-sdk-go/credentials"
	dfns_api_client "github.com/dfns/dfns-sdk-go/dfnsapiclient"
)

type KeySignerConfig struct {
	PrivateKey string  `mapstructure:"privateKey"`
	CredID     string  `mapstructure:"credId"`
	Algorithm  *string `mapstructure:"algorithm"`
}

type DfnsAPIConfig struct {
	OrgID     string  `mapstructure:"orgId"`
	AuthToken *string `mapstructure:"authToken"`
	BaseURL   string  `mapstructure:"baseUrl"`
}

type DfnsConfig struct {
	AsymmetricKeySignerConfig KeySignerConfig `mapstructure:"keySigner"`
	DfnsBaseAPIConfig         DfnsAPIConfig   `mapstructure:"api"`
}

func stringToHash(hash *string) (*crypto.Hash, error) {
	for algo := crypto.MD4; algo <= crypto.BLAKE2b_512; algo++ {
		h := crypto.Hash(algo)
		if strings.EqualFold(h.String(), strings.ToUpper(*hash)) {
			return &h, nil
		}
	}

	return nil, fmt.Errorf("hashing algorithm %s is not recognized", *hash)
}

func LoadConfig() (*DfnsConfig, error) {
	// Set defaults
	setDefaultConfig()

	viper.SetConfigFile("config.yaml")

	// Enable environment variable overwriting
	viper.AutomaticEnv()
	viper.SetEnvPrefix("DFNS")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("error reading config file %w", err)
	}

	var config DfnsConfig
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshalling config %w", err)
	}

	return &config, nil
}

func setDefaultConfig() {
	// Default values for KeySignerConfig
	viper.SetDefault("keySigner.privateKey", "")
	viper.SetDefault("keySigner.credId", "")
	viper.SetDefault("keySigner.algorithm", nil)

	// Default values for DfnsApiConfig
	viper.SetDefault("api.orgId", "")
	viper.SetDefault("api.authToken", nil)
	viper.SetDefault("api.baseUrl", "")
}

func (c *DfnsConfig) GetKeySignerConfig() (*credentials.AsymmetricKeySignerConfig, error) {
	var hashingAlgo *crypto.Hash

	if c.AsymmetricKeySignerConfig.Algorithm != nil {
		var err error

		hashingAlgo, err = stringToHash(c.AsymmetricKeySignerConfig.Algorithm)
		if err != nil {
			return nil, err
		}
	}

	return &credentials.AsymmetricKeySignerConfig{
		PrivateKey: c.AsymmetricKeySignerConfig.PrivateKey,
		CredID:     c.AsymmetricKeySignerConfig.CredID,
		Algorithm:  hashingAlgo,
	}, nil
}

func (c *DfnsConfig) GetDfnsAPIConfig() *dfns_api_client.DfnsAPIConfig {
	return &dfns_api_client.DfnsAPIConfig{
		OrgID:     c.DfnsBaseAPIConfig.OrgID,
		AuthToken: c.DfnsBaseAPIConfig.AuthToken,
		BaseURL:   c.DfnsBaseAPIConfig.BaseURL,
	}
}
