// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"io/ioutil"
	"os"

	"github.com/go-yaml/yaml"
	"github.com/signal-golang/textsecure/config"
	log "github.com/sirupsen/logrus"
)

var configFile string

// TODO: some race conditions to be solved
func checkUUID(cfg *config.Config) *config.Config {
	if len(cfg.UUID) != 36 {
		log.Debugln(cfg.UUID)
		defer func(cfg *config.Config) *config.Config {
			recover()
			UUID, err := GetMyUUID()
			if err != nil {
				log.Debugln("[textsecure] missing my uuid", err)
				return cfg
			}
			cfg.UUID = UUID
			return cfg
		}(cfg)
		if cfg.UUID == "notset" {
			log.Debugln("[textsecure] missing my uuid notset")
		}
	}
	return cfg
}

// ReadConfig reads a YAML config file
func ReadConfig(fileName string) (*config.Config, error) {
	b, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	configFile = fileName

	cfg := &config.Config{}
	err = yaml.Unmarshal(b, cfg)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// WriteConfig saves a config to a file
func WriteConfig(filename string, cfg *config.Config) error {
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, b, 0600)
}

func saveConfig(cfg *config.Config) error {

	log.Debugln("[textsecure] saving config", cfg.Tel)
	err := WriteConfig(configFile, cfg)
	if err != nil {
		log.Errorln("[textsecure] failed to save config", err)
		return err
	}
	return nil
}
func RefreshConfig() {
	cfg, err := loadConfig()
	if err != nil {
		log.Errorln("[textsecure] failed to load config", err)
		return
	}
	saveConfig(cfg)
}

// loadConfig gets the config via the client and makes sure
// that for unset values sane defaults are used
func loadConfig() (*config.Config, error) {
	log.Debugln("[textsecure] loading config")
	cfg, err := client.GetConfig()

	if err != nil {
		return nil, err
	}

	if cfg.Server == "" {
		cfg.Server = "https://chat.signal.org:443"
	}

	if cfg.VerificationType == "" {
		cfg.VerificationType = "sms"
	}

	if cfg.StorageDir == "" {
		cfg.StorageDir = ".storage"
	}

	return cfg, nil
}
