package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"

	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"

	"github.com/BurntSushi/toml"
	"github.com/nymsio/pgpmail"
)

const defaultConfigPath = ".nyms/verify_config"
const defaultPublicKey = ".nyms/verify_key.pub"
const defaultPrivateKey = ".nyms/verify_key.sec"
const defaultDKIMPEM = ".nyms/verify_dkim.pem"

type configData struct {
	VerifyAddress string `toml:"verify_address"`
	LogPath       string `toml:"log_path"`
	DKIMDisabled  bool   `toml:"dkim_disabled"`
	DKIMSelector  string `toml:"dkim_selector"`
	DKIMDomain    string `toml:"dkim_domain"`
	PublicKey     string `toml:"public_key"`
	PrivateKey    string `toml:"private_key"`
	DKIMKeyPEM    string `toml:dkim_key_pem"`
}

type Config struct {
	VerifyEmail    string
	LogPath        string
	KeySource      pgpmail.KeySource
	DKIMPrivatePEM []byte
	DKIMDomain     string
	DKIMSelector   string
}

func loadConfig(path string) (*Config, error) {
	if path == "" {
		path = getHomePath(defaultConfigPath)
	}
	cd := new(configData)
	_, err := toml.DecodeFile(path, cd)
	if err != nil {
		return nil, err
	}
	keySource, err := loadPGPKeys(cd)
	if err != nil {
		return nil, err
	}

	c := new(Config)
	c.VerifyEmail = cd.VerifyAddress
	c.LogPath = cd.LogPath
	c.KeySource = keySource
	if !cd.DKIMDisabled {
		dkim, err := loadDKIMPEM(cd)
		if err != nil {
			return nil, err
		}
		c.DKIMPrivatePEM = dkim
		c.DKIMDomain = cd.DKIMDomain
		c.DKIMSelector = cd.DKIMSelector
	}
	return c, nil
}

func getHomePath(subpath string) string {
	u, err := user.Current()
	if err != nil {
		panic("Could not look up current user: " + err.Error())
	}
	return filepath.Join(u.HomeDir, subpath)
}

func loadPGPKeys(cd *configData) (pgpmail.KeySource, error) {
	pub, err := loadPGPKey(cd.PublicKey, defaultPublicKey)
	if err != nil {
		return nil, err
	}

	sec, err := loadPGPKey(cd.PrivateKey, defaultPrivateKey)
	if err != nil {
		return nil, err
	}

	kr := new(pgpmail.KeyRing)
	kr.AddPublicKey(pub)
	kr.AddSecretKey(sec)
	return kr, nil
}

func loadDKIMPEM(cd *configData) ([]byte, error) {
	path := cd.DKIMKeyPEM
	if path == "" {
		path = getHomePath(defaultDKIMPEM)
	}
	pem, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load DKIM PEM file '%s': %v", path, err)
	}
	return pem, nil
}

func loadPGPKey(path string, defaultPath string) (*openpgp.Entity, error) {
	if path == "" {
		path = getHomePath(defaultPath)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	block, err := armor.Decode(f)
	if err != nil {
		return nil, err
	}
	el, err := openpgp.ReadKeyRing(block.Body)
	if err != nil {
		return nil, err
	}
	if len(el) != 1 {
		return nil, fmt.Errorf("Key file %s contained %d keys, expecting 1", path, len(el))
	}
	return el[0], nil
}
