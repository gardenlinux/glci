package credsprovider

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
	"github.com/wandb/parallel"

	"github.com/gardenlinux/glci/internal/ch"
	"github.com/gardenlinux/glci/internal/env"
	"github.com/gardenlinux/glci/internal/log"
)

func init() {
	env.Clean("VAULT_")

	registerCredsSource(func() CredsSource {
		return &vault{
			activeCreds:   make(map[CredsID]vaultCreds),
			activeSecrets: make(map[string]vaultSecret),
			events:        make(chan vaultWatchEvent),
			closeCh:       make(chan struct{}),
			errCh:         make(chan struct{}),
		}
	})
}

func (*vault) Type() string {
	return "Vault"
}

type vault struct {
	credsCfg       vaultConfig
	vaultClient    *api.Client
	vaultSecret    *api.Secret
	vaultWatcher   *api.LifetimeWatcher
	maintainExec   parallel.ErrGroupExecutor
	activeCreds    map[CredsID]vaultCreds
	activeCredsMtx sync.Mutex
	activeSecrets  map[string]vaultSecret
	events         chan vaultWatchEvent
	closeMtx       sync.Mutex
	closed         bool
	closeCh        chan struct{}
	errCh          chan struct{}
	err            error
}

type vaultConfig struct {
	Server    string `mapstructure:"server"`
	Namespace string `mapstructure:"namespace,omitzero"`
	TokenEnv  string `mapstructure:"token_env"`
	TokenFile string `mapstructure:"token_file,omitzero"`
	RoleID    string `mapstructure:"role_id,omitzero"`
	SecretID  string `mapstructure:"secret_id,omitzero"`
}

type vaultCreds struct {
	secrets  []string
	validate ValidateFunc
	updated  UpdatedFunc
}

type vaultSecret struct {
	secret  *api.Secret
	watcher *api.LifetimeWatcher
	done    chan struct{}
	owners  []CredsID
}

type vaultWatchEvent struct {
	key    string
	err    error
	secret *api.Secret
}

func (p *vault) ensureNoError() error {
	select {
	case <-p.errCh:
		return fmt.Errorf("a Vault error has been encountered: %w", p.err)
	default:
	}

	if !p.isConfigured() {
		return errors.New("config not set")
	}

	return nil
}

func (p *vault) isConfigured() bool {
	return p.credsCfg.Server != ""
}

func (p *vault) SetCredsConfig(ctx context.Context, cfg map[string]any) error {
	err := setConfig(cfg, &p.credsCfg)
	if err != nil {
		return err
	}

	c := api.DefaultConfig()
	c.Address = p.credsCfg.Server

	p.vaultClient, err = api.NewClient(c)
	if err != nil {
		return fmt.Errorf("cannot create client: %w", err)
	}

	if p.credsCfg.Namespace != "" {
		p.vaultClient.SetNamespace(p.credsCfg.Namespace)
	}

	err = p.reestablishVault(ctx)
	if err != nil {
		return err
	}

	p.maintainExec = parallel.ErrGroup(parallel.Limited(ctx, 1))
	p.maintainExec.Go(func(ctx context.Context) error {
		err = p.maintain(ctx)
		if err != nil {
			log.Error(ctx, err)
			p.err = err
			close(p.errCh)
		}
		return err
	})

	return nil
}

func (p *vault) maintain(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-p.closeCh:
			return nil

		default:
		}

		retry, err := p.maintainVault(ctx)
		if err != nil || !retry {
			return err
		}

		err = p.reestablishVault(ctx)
		if err != nil {
			return err
		}
	}
}

func (p *vault) maintainVault(ctx context.Context) (bool, error) {
	var err error
	p.vaultWatcher, err = p.vaultClient.NewLifetimeWatcher(&api.LifetimeWatcherInput{
		Secret: p.vaultSecret,
	})
	if err != nil {
		return false, fmt.Errorf("cannot set up token renewal: %w", err)
	}

	go p.vaultWatcher.Start()
	defer p.vaultWatcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()

		case <-p.closeCh:
			return false, nil

		case err = <-p.vaultWatcher.DoneCh():
			if err != nil {
				if errors.Is(err, api.ErrLifetimeWatcherNotRenewable) {
					continue
				}

				log.Error(ctx, fmt.Errorf("cannot renew Vault credentials: %w", err))
			}
			return true, nil

		case <-p.vaultWatcher.RenewCh():
			log.Info(ctx, "Vault credentials renewed")

		case event := <-p.events:
			if event.secret != nil {
				log.Debug(ctx, "Vault secret renewed", "key", event.key)
				continue
			}

			if event.err != nil {
				log.Error(ctx, fmt.Errorf("cannot renew Vault secret %s: %w", event.key, event.err))
			}

			err = p.processWatchEvent(ctx, event)
			if err != nil {
				return false, err
			}
		}
	}
}

func (p *vault) processWatchEvent(ctx context.Context, event vaultWatchEvent) error {
	p.activeCredsMtx.Lock()
	defer p.activeCredsMtx.Unlock()

	ctx = log.WithValues(ctx, "vaultKey", event.key)

	secret, ok := p.activeSecrets[event.key]
	if !ok {
		return fmt.Errorf("inconsistent internal state for secret %s: secret not active", event.key)
	}

	p.deactivateSecret(event.key, secret)
	var err error
	secret, err = p.activateSecret(ctx, event.key, secret.owners)
	if err != nil {
		return fmt.Errorf("cannot acquire Vault secret %s: %w", event.key, err)
	}

	for _, owner := range secret.owners {
		var creds vaultCreds
		creds, ok = p.activeCreds[owner]
		if !ok {
			return fmt.Errorf("inconsistent internal state for secret %s: credentials %s/%s not active", event.key, owner.Type,
				owner.Config)
		}

		err = p.validateAndAnnounceNewCreds(ctx, creds)
		if err != nil {
			return fmt.Errorf("cannot update credentials %s/%s: %w", owner.Type, owner.Config, err)
		}
	}

	return nil
}

func (p *vault) reestablishVault(ctx context.Context) error {
	p.activeCredsMtx.Lock()
	defer p.activeCredsMtx.Unlock()

	for key, secret := range p.activeSecrets {
		p.deactivateSecret(key, secret)
	}
	ch.Drain(p.events)
	p.activeSecrets = make(map[string]vaultSecret)
	inactiveCreds := p.activeCreds
	p.activeCreds = make(map[CredsID]vaultCreds)

	err := p.login(ctx)
	if err != nil {
		return fmt.Errorf("cannot log in to Vault: %w", err)
	}

	for id, creds := range inactiveCreds {
		err = p.renewCreds(ctx, id, creds.validate, creds.updated)
		if err != nil {
			return fmt.Errorf("cannot renew credentials %s/%s: %w", id.Type, id.Config, err)
		}
	}

	return nil
}

func (p *vault) login(ctx context.Context) error {
	log.Info(ctx, "Logging in to Vault")

	switch {
	case p.credsCfg.TokenEnv != "":
		log.Debug(ctx, "Using provided token")

		token := strings.TrimSpace(os.Getenv(p.credsCfg.TokenEnv))
		if token == "" {
			return fmt.Errorf("token environment varriable %s empty or missing", p.credsCfg.TokenEnv)
		}
		p.vaultClient.SetToken(token)
		var err error
		p.vaultSecret, err = p.vaultClient.Auth().Token().LookupSelfWithContext(ctx)
		return err

	case p.credsCfg.TokenFile != "":
		log.Debug(ctx, "Using provided token")
		t, err := os.ReadFile(p.credsCfg.TokenFile)
		if err != nil {
			return fmt.Errorf("cannot read token file %s: %w", p.credsCfg.TokenFile, err)
		}
		p.vaultClient.SetToken(strings.TrimSpace(string(t)))
		p.vaultSecret, err = p.vaultClient.Auth().Token().LookupSelfWithContext(ctx)
		return err

	case p.credsCfg.RoleID != "" && p.credsCfg.SecretID != "":
		log.Debug(ctx, "Using AppRole")
		appRole, err := approle.NewAppRoleAuth(p.credsCfg.RoleID, &approle.SecretID{
			FromString: p.credsCfg.SecretID,
		})
		if err != nil {
			return fmt.Errorf("cannot create AppRole: %w", err)
		}
		p.vaultSecret, err = p.vaultClient.Auth().Login(ctx, appRole)
		if err != nil {
			return fmt.Errorf("cannot login using AppRole: %w", err)
		}
		return nil

	default:
		return errors.New("missing Vault credentials")
	}
}

func (*vault) secretKeys(id CredsID) []string {
	switch id.Type {
	case "Aliyun":
		return []string{
			fmt.Sprintf("se-alicloud-%s/creds/glci", id.Config),
		}
	case "AWS":
		return []string{
			fmt.Sprintf("se-aws-%s/creds/glci", id.Config),
		}
	case "AWS_china":
		return []string{
			fmt.Sprintf("se-aws-%s/data/creds/glci", id.Config),
		}
	case "Azure":
		return []string{
			fmt.Sprintf("se-azure-%s/config", id.Config),
			fmt.Sprintf("se-azure-%s/creds/glci", id.Config),
		}
	case "Azure_china":
		return []string{
			fmt.Sprintf("se-azure-%s/data/creds/glci", id.Config),
		}
	case "Azure_storage":
		return []string{
			fmt.Sprintf("se-azure_storage-%s/data/creds", id.Config),
		}
	case "GCP":
		return []string{
			fmt.Sprintf("se-gcp-%s/impersonated-account/glci", id.Config),
			fmt.Sprintf("se-gcp-%s/impersonated-account/glci/token", id.Config),
		}
	case "OCI_GCP":
		return []string{
			fmt.Sprintf("se-gcp-%s/impersonated-account/glci/token", id.Config),
		}
	case "OpenStack":
		return []string{
			fmt.Sprintf("se-sci-%s/data/creds", id.Config),
		}
	default:
		return []string{
			fmt.Sprintf("se-%s/data/creds", id.Config),
		}
	}
}

func (p *vault) AcquireCreds(ctx context.Context, id CredsID, updated UpdatedFunc) error {
	return p.AcquireValidatedCreds(ctx, id, nil, updated)
}

func (p *vault) AcquireValidatedCreds(ctx context.Context, id CredsID, validate ValidateFunc, updated UpdatedFunc) error {
	err := p.ensureNoError()
	if err != nil {
		return err
	}

	p.activeCredsMtx.Lock()
	defer p.activeCredsMtx.Unlock()

	creds, ok := p.activeCreds[id]
	if ok {
		ctx = log.WithValues(ctx, "credsType", id.Type, "credsConfig", id.Config)

		creds.validate = validate
		creds.updated = updated
		p.activeCreds[id] = creds

		err = p.validateAndAnnounceNewCreds(ctx, creds)
		if err != nil {
			return fmt.Errorf("cannot update credentials %s/%s: %w", id.Type, id.Config, err)
		}

		return nil
	}

	err = p.renewCreds(ctx, id, validate, updated)
	if err != nil {
		return fmt.Errorf("cannot renew credentials %s/%s: %w", id.Type, id.Config, err)
	}

	return nil
}

func (p *vault) validateAndAnnounceNewCreds(ctx context.Context, creds vaultCreds) error {
	allData := make(map[string]any)
	for _, key := range creds.secrets {
		secret, ok := p.activeSecrets[key]
		if !ok {
			return fmt.Errorf("inconsistent internal state for secret %s: secret not active", key)
		}
		var secretData map[string]any
		secretData, ok = secret.secret.Data["data"].(map[string]any)
		if !ok {
			secretData = secret.secret.Data
		}
		maps.Copy(allData, secretData)
	}

	if creds.validate != nil {
		err := p.validateCreds(ctx, creds.validate, allData)
		if err != nil {
			return fmt.Errorf("cannot validate credentials: %w", err)
		}
	}

	return creds.updated(ctx, allData)
}

func (*vault) validateCreds(ctx context.Context, validate ValidateFunc, data map[string]any) error {
	var success int
	var best int
	var err error
	for success < 3 {
		var attempt int
		var good bool
		for attempt < 11 {
			if attempt == 0 && success >= best {
				log.Debug(ctx, "Validating credentials", "success", success)
			}
			good, err = validate(ctx, data)
			if err != nil {
				return err
			}
			if good {
				success++
				if success > best {
					best = success
				}
				break
			}
			time.Sleep(time.Second * 3)
			attempt++
			success = 0
		}
		if !good {
			return errors.New("maximum number of attempts exceeded")
		}
	}

	return nil
}

func (p *vault) renewCreds(ctx context.Context, id CredsID, validate ValidateFunc, updated UpdatedFunc) error {
	ctx = log.WithValues(ctx, "credsType", id.Type, "credsConfig", id.Config)

	keys := p.secretKeys(id)
	for _, key := range keys {
		lctx := log.WithValues(ctx, "vaultKey", key)

		err := p.acquireSecret(lctx, key, id)
		if err != nil {
			return err
		}
	}

	creds := vaultCreds{
		secrets:  keys,
		validate: validate,
		updated:  updated,
	}
	p.activeCreds[id] = creds

	err := p.validateAndAnnounceNewCreds(ctx, creds)
	if err != nil {
		return fmt.Errorf("cannot update credentials %s/%s: %w", id.Type, id.Config, err)
	}

	return nil
}

func (p *vault) acquireSecret(ctx context.Context, key string, owner CredsID) error {
	secret, ok := p.activeSecrets[key]
	if ok {
		if slices.Contains(secret.owners, owner) {
			return fmt.Errorf("inconsistent internal state for secret %s: secret already owned by credentials %s/%s", key, owner.Type,
				owner.Config)
		}
		secret.owners = append(secret.owners, owner)
		p.activeSecrets[key] = secret
		return nil
	}

	var err error
	_, err = p.activateSecret(ctx, key, []CredsID{
		owner,
	})
	if err != nil {
		return fmt.Errorf("cannot acquire Vault secret %s: %w", key, err)
	}

	return nil
}

func (p *vault) activateSecret(ctx context.Context, key string, owners []CredsID) (vaultSecret, error) {
	var secret vaultSecret
	var err error

	log.Debug(ctx, "Reading Vault secret")
	secret.secret, err = p.vaultClient.Logical().ReadWithContext(ctx, key)
	if err != nil {
		return vaultSecret{}, fmt.Errorf("cannot get secret: %w", err)
	}
	if secret.secret == nil {
		return vaultSecret{}, errors.New("cannot get secret: secret is nil")
	}
	if secret.secret.Data == nil {
		return vaultSecret{}, errors.New("cannot get secret: secret has no data")
	}

	secret.watcher, err = p.vaultClient.NewLifetimeWatcher(&api.LifetimeWatcherInput{
		Secret: secret.secret,
	})
	if err != nil {
		return vaultSecret{}, fmt.Errorf("cannot set up token renewal: %w", err)
	}

	secret.done = make(chan struct{})

	secret.owners = owners

	p.activeSecrets[key] = secret

	go secret.watcher.Start()
	go p.monitor(secret.done, key, secret.watcher)

	return secret, nil
}

func (p *vault) monitor(done <-chan struct{}, key string, watcher *api.LifetimeWatcher) {
	for {
		select {
		case <-done:
			return

		case err := <-watcher.DoneCh():
			select {
			case <-done:
				return
			default:
			}

			if errors.Is(err, api.ErrLifetimeWatcherNotRenewable) {
				return
			}

			p.events <- vaultWatchEvent{
				key: key,
				err: err,
			}

		case renewal := <-watcher.RenewCh():
			select {
			case <-done:
				return
			default:
			}

			p.events <- vaultWatchEvent{
				key:    key,
				secret: renewal.Secret,
			}
		}
	}
}

func (p *vault) ReleaseCreds(id CredsID) {
	err := p.ensureNoError()
	if err != nil {
		return
	}

	p.activeCredsMtx.Lock()
	defer p.activeCredsMtx.Unlock()

	creds, ok := p.activeCreds[id]
	if !ok {
		return
	}

	for _, key := range creds.secrets {
		p.releaseSecret(key, id)
	}

	delete(p.activeCreds, id)
}

func (p *vault) releaseSecret(key string, owner CredsID) {
	secret, ok := p.activeSecrets[key]
	if !ok {
		return
	}

	for i, o := range secret.owners {
		if o == owner {
			if len(secret.owners) == 1 {
				p.deactivateSecret(key, secret)
				return
			}

			secret.owners = slices.Delete(secret.owners, i, i+1)
			p.activeSecrets[key] = secret
			return
		}
	}
}

func (p *vault) deactivateSecret(key string, secret vaultSecret) {
	close(secret.done)
	secret.watcher.Stop()

	delete(p.activeSecrets, key)
}

func (p *vault) Close() error {
	p.closeMtx.Lock()
	defer p.closeMtx.Unlock()

	if p.closed {
		return nil
	}

	close(p.closeCh)
	p.closed = true

	if p.maintainExec != nil {
		err := p.maintainExec.Wait()
		if err != nil {
			return fmt.Errorf("error encountered while renewing credentials: %w", err)
		}
	}

	return nil
}
