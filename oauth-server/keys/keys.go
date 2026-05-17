package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type KeyInfo struct {
	Kid     string
	PubKey  *rsa.PublicKey
	privKey *rsa.PrivateKey
}

func (ki *KeyInfo) GetPrivateKey() *rsa.PrivateKey {
	return ki.privKey
}

type KeyManager struct {
	mu        sync.RWMutex
	keys      map[string]*rsa.PrivateKey
	activeKid string
	dir       string
}

const oldKeyTTL = 30 * 24 * time.Hour

func generateKid(version int) string {
	date := time.Now().Format("2006-01-02")
	return fmt.Sprintf("v%d-%s", version, date)
}

func getKeyPath(dir, kid string) string {
	return filepath.Join(dir, kid+".pem")
}

func NewKeyManager(dir string) *KeyManager {
	km := &KeyManager{
		keys: make(map[string]*rsa.PrivateKey), dir: dir,
	}
	km.setup(dir)
	return km
}

// loadOrGenerate loads a PEM-encoded RSA private key from path,
// or generates a new one, saves it, and returns it.
func loadOrGenerate(path string) (*rsa.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block != nil && block.Type == "RSA PRIVATE KEY" {
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err == nil {
				return key, nil
			}
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("save rsa key: %w", err)
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}); err != nil {
		return nil, err
	}

	return key, nil
}

func (km *KeyManager) setup(dir string) {
	km.mu.Lock()
	defer km.mu.Unlock()

	dir, _ = filepath.Abs(dir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Fatalf("Unable to create key directory: %v", err)
	}

	files, _ := os.ReadDir(dir)
	if len(files) == 0 {
		var kid string = generateKid(1)
		privKey, _ := loadOrGenerate(getKeyPath(dir, kid))
		km.keys[kid] = privKey
		km.activeKid = kid
		return
	}

	var latest string
	for _, f := range files {
		kid := strings.TrimSuffix(f.Name(), ".pem")
		pemData, _ := os.ReadFile(filepath.Join(dir, f.Name()))
		block, _ := pem.Decode(pemData)
		if block == nil {
			log.Fatalf("Unable to read private key: %s", f.Name())
			continue
		}
		privKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

		km.keys[kid] = privKey
		if kid > latest {
			latest = kid
		}
	}
	km.activeKid = latest
	km.pruneExpiredKeysLocked(time.Now())
}

func (km *KeyManager) GetKeyInfos() []KeyInfo {
	km.mu.RLock()
	defer km.mu.RUnlock()

	var infos []KeyInfo
	for kid, priv := range km.keys {
		infos = append(infos, KeyInfo{
			Kid:     kid,
			PubKey:  &priv.PublicKey,
			privKey: priv,
		})
	}
	return infos
}

func (km *KeyManager) GetActiveKey() KeyInfo {
	km.mu.RLock()
	defer km.mu.RUnlock()

	return KeyInfo{Kid: km.activeKid, PubKey: &km.keys[km.activeKid].PublicKey, privKey: km.keys[km.activeKid]}
}

// ParseJWT First parses the token unverified to get the kid
// after getting the kid, fetches the public key
func (km *KeyManager) ParseJWT(token string) (*jwt.Token, error) {
	parser := jwt.NewParser()
	unverifiedToken, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	kid, ok := unverifiedToken.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("missing kid in token header")
	}

	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		km.mu.RLock()
		privKey, exists := km.keys[kid]
		km.mu.RUnlock()

		if !exists {
			return nil, fmt.Errorf("unknown kid: %s", kid)
		}

		return &privKey.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
}

func (km *KeyManager) Rotate() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	version := len(km.keys) + 1
	kid := generateKid(version)
	privKey, err := loadOrGenerate(getKeyPath(km.dir, kid))
	if err != nil {
		return err
	}

	km.keys[kid] = privKey
	km.activeKid = kid
	km.pruneExpiredKeysLocked(time.Now())

	return nil
}

func (km *KeyManager) pruneExpiredKeysLocked(now time.Time) {
	cutoff := now.Add(-oldKeyTTL)

	for kid := range km.keys {
		if kid == km.activeKid {
			continue
		}

		keyPath := getKeyPath(km.dir, kid)
		info, err := os.Stat(keyPath)
		if err != nil {
			continue
		}
		if !info.ModTime().Before(cutoff) {
			continue
		}

		delete(km.keys, kid)
		if err := os.Remove(keyPath); err != nil && !os.IsNotExist(err) {
			log.Printf("failed to remove expired key %s: %v", kid, err)
		}
	}
}
