package vaultinit

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"

	"github.com/edgexfoundry/edgex-go/internal/security/secretstore/config"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/clients/logger"
	"github.com/edgexfoundry/go-mod-secrets/v2/pkg/token/fileioperformer"
	"github.com/edgexfoundry/go-mod-secrets/v2/pkg/types"
	"github.com/edgexfoundry/go-mod-secrets/v2/secrets"
)

type VaultInit struct {
	logging      logger.LoggingClient
	secretClient secrets.SecretStoreClient
	secretConfig config.SecretStoreInfo
	fileOpener   fileioperformer.FileIoPerformer
	initialized  bool
}

// NewTokenMaintenance creates a new TokenProvider
func NewVaultInit(logging logger.LoggingClient, secretClient secrets.SecretStoreClient, secretConfig config.SecretStoreInfo, fileOpener fileioperformer.FileIoPerformer) *VaultInit {
	return &VaultInit{
		logging:      logging,
		secretClient: secretClient,
		secretConfig: secretConfig,
		fileOpener:   fileOpener,
	}
}

func (vi *VaultInit) InitializeVault() (sCode int, initResponse types.InitResponse, err error) {
	// sCode, _ := vi.secretClient.HealthCheck()
	vi.initialized := false
	switch sCode, _ := vi.secretClient.HealthCheck(); sCode {
	case http.StatusOK:
		// Load the init response from disk since we need it to regenerate root token later
		if err := loadInitResponse(vi.logging, vi.fileOpener, vi.secretConfig, &initResponse); err != nil {
			vi.logging.Errorf("unable to load init response: %s", err.Error())
			return sCode, initResponse, err
		}
		vi.logging.Infof("vault is initialized and unsealed (status code: %d)", sCode)
		return sCode, initResponse, err
	case http.StatusTooManyRequests:
		// we're done here. Will go into ready mode or reseal
		//shouldContinue = false

		// Q: This status seems like we should be returning an error
	case http.StatusNotImplemented:
		vi.logging.Infof("vault is not initialized (status code: %d). Starting initialization and unseal phases", sCode)
		initResponse, err = vi.secretClient.Init(vi.secretConfig.VaultSecretThreshold, vi.secretConfig.VaultSecretShares)
		if err != nil {
			vi.logging.Errorf("Unable to Initialize Vault: %s. Will try again...", err.Error())
			// Not terminal failure, should continue and try again
			return sCode, initResponse, err
		}

		if vi.secretConfig.RevokeRootTokens {
			// Never persist the root token to disk on secret store initialization if we intend to revoke it later
			initResponse.RootToken = ""
			vi.logging.Info("Root token stripped from init response for security reasons")
		}
	case http.StatusServiceUnavailable:
		vi.logging.Infof("vault is sealed (status code: %d). Starting unseal phase", sCode)
		if err := loadInitResponse(vi.logging, vi.fileOpener, vi.secretConfig, &initResponse); err != nil {
			vi.logging.Errorf("unable to load init response: %s", err.Error())
			return sCode, initResponse, err
		}
	default:
		if sCode == 0 {
			vi.logging.Errorf("vault is in an unknown state. No Status code available")
		} else {
			vi.logging.Errorf("vault is in an unknown state. Status code: %d", sCode)
		}
	}
	return sCode, initResponse, err
}

func loadInitResponse(
	lc logger.LoggingClient,
	fileOpener fileioperformer.FileIoPerformer,
	secretConfig config.SecretStoreInfo,
	initResponse *types.InitResponse) error {

	absPath := filepath.Join(secretConfig.TokenFolderPath, secretConfig.TokenFile)

	tokenFile, err := fileOpener.OpenFileReader(absPath, os.O_RDONLY, 0400)
	if err != nil {
		lc.Errorf("could not read master key shares file %s: %s", absPath, err.Error())
		return err
	}
	tokenFileCloseable := fileioperformer.MakeReadCloser(tokenFile)
	defer func() { _ = tokenFileCloseable.Close() }()

	decoder := json.NewDecoder(tokenFileCloseable)
	if decoder == nil {
		err := errors.New("Failed to create JSON decoder")
		lc.Error(err.Error())
		return err
	}
	if err := decoder.Decode(initResponse); err != nil {
		lc.Errorf("unable to read token file at %s with error: %s", absPath, err.Error())
		return err
	}

	return nil
}

func saveInitResponse(
	lc logger.LoggingClient,
	fileOpener fileioperformer.FileIoPerformer,
	secretConfig config.SecretStoreInfo,
	initResponse *types.InitResponse) error {

	absPath := filepath.Join(secretConfig.TokenFolderPath, secretConfig.TokenFile)

	tokenFile, err := fileOpener.OpenFileWriter(absPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		lc.Errorf("could not read master key shares file %s: %s", absPath, err.Error())
		return err
	}

	encoder := json.NewEncoder(tokenFile)
	if encoder == nil {
		err := errors.New("Failed to create JSON encoder")
		lc.Error(err.Error())
		_ = tokenFile.Close()
		return err
	}
	if err := encoder.Encode(initResponse); err != nil {
		lc.Errorf("unable to write token file at %s with error: %s", absPath, err.Error())
		_ = tokenFile.Close()
		return err
	}

	if err := tokenFile.Close(); err != nil {
		lc.Errorf("unable to close token file at %s with error: %s", absPath, err.Error())
		_ = tokenFile.Close()
		return err
	}

	return nil
}
