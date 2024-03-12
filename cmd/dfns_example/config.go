package main

import (
	"crypto"
	"fmt"
	"strings"

	"github.com/spf13/viper"
	"github/dfns/dfns-sdk-go/pkg/credentials"
	dfns_api_client "github/dfns/dfns-sdk-go/pkg/dfns-api-client"
)

type KeySignerConfig struct {
	PrivateKey  string  `mapstructure:"privateKey"`
	CredId      string  `mapstructure:"credId"`
	AppOrigin   string  `mapstructure:"appOrigin"`
	CrossOrigin *bool   `mapstructure:"crossOrigin"`
	Algorithm   *string `mapstructure:"algorithm"`
}

type DfnsApiConfig struct {
	AppId     string  `mapstructure:"appId"`
	AuthToken *string `mapstructure:"authToken"`
	BaseUrl   string  `mapstructure:"baseUrl"`
}

type DfnsConfig struct {
	AsymmetricKeySignerConfig KeySignerConfig `mapstructure:"keySigner"`
	DfnsBaseApiConfig         DfnsApiConfig   `mapstructure:"api"`
}

func stringToHash(hash *string) (*crypto.Hash, error) {
	if hash == nil {
		return nil, nil
	}

	for i := crypto.MD4; i <= crypto.BLAKE2b_512; i++ {
		h := crypto.Hash(i) //nolint
		if strings.EqualFold(h.String(), strings.ToUpper(*hash)) {
			return &h, nil
		}
		i++
	}

	return nil, fmt.Errorf("hashing algorithm %s is not recognized", *hash)
}

func LoadConfig() *DfnsConfig {
	// Set defaults
	setDefaultConfig()

	viper.SetConfigFile("config.yaml")

	// Enable environment variable overwriting
	viper.AutomaticEnv()
	viper.SetEnvPrefix("DFNS")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Error reading config file: %s\n", err)

		return nil
	}

	var config DfnsConfig
	if err := viper.Unmarshal(&config); err != nil {
		fmt.Printf("Error unmarshalling config: %s\n", err)

		return nil
	}

	return &config
}

func setDefaultConfig() {
	// Default values for KeySignerConfig
	viper.SetDefault("keySigner.privateKey", "")
	viper.SetDefault("keySigner.credId", "")
	viper.SetDefault("keySigner.appOrigin", "")
	viper.SetDefault("keySigner.crossOrigin", nil)
	viper.SetDefault("keySigner.algorithm", nil)

	// Default values for DfnsApiConfig
	viper.SetDefault("api.appId", "")
	viper.SetDefault("api.authToken", nil)
	viper.SetDefault("api.baseUrl", "")
}

func (c *DfnsConfig) GetKeySignerConfig() (*credentials.AsymmetricKeySignerConfig, error) {
	h, err := stringToHash(c.AsymmetricKeySignerConfig.Algorithm)
	if err != nil {
		return nil, err
	}

	return &credentials.AsymmetricKeySignerConfig{
		PrivateKey:  c.AsymmetricKeySignerConfig.PrivateKey,
		CredId:      c.AsymmetricKeySignerConfig.CredId,
		AppOrigin:   c.AsymmetricKeySignerConfig.AppOrigin,
		CrossOrigin: c.AsymmetricKeySignerConfig.CrossOrigin,
		Algorithm:   h,
	}, nil
}

func (c *DfnsConfig) GetDfnsApiConfig() *dfns_api_client.DfnsApiConfig {
	return &dfns_api_client.DfnsApiConfig{
		AppId:     c.DfnsBaseApiConfig.AppId,
		AuthToken: c.DfnsBaseApiConfig.AuthToken,
		BaseUrl:   c.DfnsBaseApiConfig.BaseUrl,
	}
}
