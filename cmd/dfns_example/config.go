package main

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"

	dfns "github.com/dfns/dfns-sdk-go"
	"github.com/dfns/dfns-sdk-go/signer"
)

type KeySignerConfig struct {
	PrivateKey string `mapstructure:"privateKey"`
	CredID     string `mapstructure:"credId"`
}

type DfnsAPIConfig struct {
	AuthToken *string `mapstructure:"authToken"`
	BaseURL   string  `mapstructure:"baseUrl"`
}

type DfnsConfig struct {
	AsymmetricKeySignerConfig KeySignerConfig `mapstructure:"keySigner"`
	DfnsBaseAPIConfig         DfnsAPIConfig   `mapstructure:"api"`
}

func LoadConfig() (*DfnsConfig, error) {
	setDefaultConfig()

	viper.SetConfigFile("config.yaml")

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
	viper.SetDefault("keySigner.privateKey", "")
	viper.SetDefault("keySigner.credId", "")

	viper.SetDefault("api.authToken", nil)
	viper.SetDefault("api.baseUrl", "")
}

func (c *DfnsConfig) NewDfnsClient() (*dfns.Client, error) {
	s, err := signer.NewKeySigner(c.AsymmetricKeySignerConfig.CredID, c.AsymmetricKeySignerConfig.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error creating key signer: %w", err)
	}

	authToken := ""
	if c.DfnsBaseAPIConfig.AuthToken != nil {
		authToken = *c.DfnsBaseAPIConfig.AuthToken
	}

	return dfns.NewClient(dfns.Options{
		BaseURL:   c.DfnsBaseAPIConfig.BaseURL,
		AuthToken: authToken,
		Signer:    s,
	})
}
