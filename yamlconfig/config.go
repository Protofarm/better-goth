package config

import (
	"go.yaml.in/yaml/v4"
)

type Config struct {
	App struct {
		Port         string `yaml:"port"`
		Scheme       string `yaml:"scheme"`
		DevMode      bool   `yaml:"dev_mode"`
		CookieSecure bool   `yaml:"cookie_secure"`
	} `yaml:"app"`

	Providers struct {
		OAuthServer struct {
			Enabled      bool     `yaml:"enabled"`
			Port         string   `yaml:"port"`
			IssuerURL    string   `yaml:"issuer_url"`
			ClientID     string   `yaml:"client_id"`
			ClientSecret string   `yaml:"client_secret"`
			KeyDir       string   `yaml:"key_dir"`
			AuthHTMLPath string   `yaml:"auth_html_path"`
			RedirectURIs []string `yaml:"redirect_uris"`
			TLS          struct {
				Enabled  bool   `yaml:"enabled"`
				CertPath string `yaml:"cert_path"`
				KeyPath  string `yaml:"key_path"`
			} `yaml:"tls"`
		} `yaml:"oauthserver"`
		Google struct {
			Enabled      bool   `yaml:"enabled"`
			ClientID     string `yaml:"client_id"`
			ClientSecret string `yaml:"client_secret"`
			RedirectURI  string `yaml:"redirect_uri"`
		} `yaml:"google"`
		GitHub struct {
			Enabled      bool   `yaml:"enabled"`
			ClientID     string `yaml:"client_id"`
			ClientSecret string `yaml:"client_secret"`
		} `yaml:"github"`
	} `yaml:"providers"`

	JWT struct {
		Secret     string `yaml:"secret"`
		CookieName string `yaml:"cookie_name"`
	} `yaml:"jwt"`

	Storage struct {
		Type             string `yaml:"type"`
		ConnectionString string `yaml:"connection_string"`
	} `yaml:"storage"`

	Templates struct {
		Path    string `yaml:"path"`
		Preload bool   `yaml:"preload"`
	} `yaml:"templates"`

	Logging struct {
		Level  string `yaml:"level"`
		Format string `yaml:"format"`
	} `yaml:"logging"`
}

func LoadConfig(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
