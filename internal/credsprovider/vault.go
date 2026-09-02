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

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
	"github.com/wandb/parallel"

	"github.com/gardenlinux/glci/internal/env"
	"github.com/gardenlinux/glci/internal/guard"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/module"
)

//nolint:gochecknoinits // Required for automatic registration.
func init() {
	env.Clean("VAULT_")

	module.RegisterImpl(Category, "Vault", func(b *module.Base) CredsSource {
		return &vault{
			base:            b,
			retrier:         guard.NewRetrier(guard.DelegatingRetryPolicy{}, guard.DelegatingTimeoutPolicy{}),
			conflictRetrier: guard.NewRetrier(guard.NewConflictAwarePolicy(guard.DelegatingRetryPolicy{}), guard.DelegatingTimeoutPolicy{}),
			activeCreds:     make(map[CredsID]*vaultCreds),
			activeSecrets:   make(map[string]*vaultSecret),
			events:          make(chan vaultWatchEvent),
			closeCh:         make(chan struct{}),
			errCh:           make(chan struct{}),
		}
	})
}

type vault struct {
	base *module.Base

	credsCfg        vaultConfig
	vaultClient     *api.Client
	vaultSecret     *api.Secret
	vaultWatcher    *api.LifetimeWatcher
	retrier         guard.Retrier
	conflictRetrier guard.Retrier
	maintainExec    parallel.ErrGroupExecutor

	loginMtx        sync.Mutex
	loginGeneration uint64
	ownToken        bool
	activeCreds     map[CredsID]*vaultCreds
	activeSecrets   map[string]*vaultSecret

	events chan vaultWatchEvent

	closeMtx sync.Mutex
	closed   bool

	closeCh chan struct{}
	errCh   chan struct{}
	err     error
}

type vaultConfig struct {
	Server    string `mapstructure:"server"`
	Namespace string `mapstructure:"namespace,omitzero"`

	Token     string `mapstructure:"token,omitzero"`
	TokenFile string `mapstructure:"token_file,omitzero"`

	RoleID   string `mapstructure:"role_id,omitzero"`
	SecretID string `mapstructure:"secret_id,omitzero"`

	JWT          string `mapstructure:"jwt,omitzero"`
	JWTMountPath string `mapstructure:"jwt_mount_path,omitzero"`
	JWTRole      string `mapstructure:"jwt_role,omitzero"`
}

type vaultCreds struct {
	secrets  []string
	acquired bool

	applyMtx sync.Mutex
	apply    ApplyCredsFunc
}

type vaultSecret struct {
	watcher *api.LifetimeWatcher
	done    chan struct{}
	owners  []CredsID

	secretMtx sync.Mutex
	secret    *api.Secret
}

type vaultWatchEvent struct {
	key    string
	err    error
	secret *api.Secret
}

func (p *vault) Configure(rawCfg map[string]any) error {
	err := parseConfig(rawCfg, &p.credsCfg)
	if err != nil {
		return err
	}

	c := api.DefaultConfig()
	c.Address = p.credsCfg.Server
	c.MaxRetries = guard.Retries
	c.MinRetryWait = guard.RetryBaseDelay
	c.MaxRetryWait = guard.RetryMaxDelay
	c.Timeout = guard.Timeout

	p.vaultClient, err = api.NewClient(c)
	if err != nil {
		return fmt.Errorf("cannot create client: %w", err)
	}

	if p.credsCfg.Namespace != "" {
		p.vaultClient.SetNamespace(p.credsCfg.Namespace)
	}

	return nil
}

func (*vault) Configurables() []module.Configurable {
	return nil
}

func (p *vault) Start(ctx context.Context) error {
	err := p.reestablishVault(ctx)
	if err != nil {
		return err
	}

	p.maintainExec = parallel.ErrGroup(parallel.Limited(ctx, 1))
	p.maintainExec.Go(func(ctx context.Context) error {
		inErr := p.maintain(ctx)
		if inErr != nil {
			log.Error(ctx, inErr)
			p.err = inErr
			close(p.errCh)
		}

		return inErr
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

		shouldReestablish, err := p.maintainVault(ctx)
		if err != nil || !shouldReestablish {
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
				log.Debug(ctx, "Vault secret renewed", "vaultKey", event.key)
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
	ctx = log.WithValues(ctx, "vaultKey", event.key)

	err := p.renewSecret(ctx, event.key)
	if err != nil {
		return fmt.Errorf("cannot renew Vault secret %s: %w", event.key, err)
	}

	var owners []CredsID
	func() {
		p.loginMtx.Lock()
		defer p.loginMtx.Unlock()

		secret, ok := p.activeSecrets[event.key]
		if ok {
			owners = slices.Clone(secret.owners)
		}
	}()

	for _, owner := range owners {
		err = p.deliverCreds(ctx, owner, nil)
		if err != nil {
			return fmt.Errorf("cannot update credentials %s/%s/%s: %w", owner.Type, owner.Config, owner.Role, err)
		}
	}

	return nil
}

func (p *vault) renewSecret(ctx context.Context, key string) error {
	var startGen uint64
	var secret *vaultSecret
	var ok bool
	func() {
		p.loginMtx.Lock()
		defer p.loginMtx.Unlock()

		startGen = p.loginGeneration
		secret, ok = p.activeSecrets[key]
	}()
	if !ok {
		return nil
	}

	secret.secretMtx.Lock()
	defer secret.secretMtx.Unlock()

	s, w, err := p.readSecret(ctx, key)
	if err != nil {
		return err
	}

	p.loginMtx.Lock()
	defer p.loginMtx.Unlock()

	if p.loginGeneration != startGen || p.activeSecrets[key] != secret {
		if s.LeaseID != "" {
			go p.revokeSecret(ctx, s.LeaseID)
		}

		return nil
	}
	if secret.done != nil {
		close(secret.done)
	}
	if secret.watcher != nil {
		secret.watcher.Stop()
	}

	secret.watcher = w
	secret.done = make(chan struct{})
	secret.secret = s

	go secret.watcher.Start()
	go p.monitor(secret.done, key, secret.watcher)

	return nil
}

func (p *vault) reestablishVault(ctx context.Context) error {
	var retiredClient *api.Client
	var activeIDs []CredsID
	err := func() error {
		p.loginMtx.Lock()
		defer p.loginMtx.Unlock()

		for key, secret := range p.activeSecrets {
			p.deactivateSecret(key, secret)
		}

		if p.ownToken && p.vaultClient.Token() != "" {
			var inErr error
			retiredClient, inErr = p.vaultClient.Clone()
			if inErr != nil {
				return fmt.Errorf("cannot clone client: %w", inErr)
			}

			retiredClient.SetToken(p.vaultClient.Token())
		}

		inErr := p.login(ctx)
		if inErr != nil {
			return fmt.Errorf("cannot log in to Vault: %w", inErr)
		}

		p.loginGeneration++

		activeIDs = make([]CredsID, 0, len(p.activeCreds))
		for id := range p.activeCreds {
			activeIDs = append(activeIDs, id)
		}

		return nil
	}()
	if err != nil {
		return err
	}

	for _, id := range activeIDs {
		err = p.deliverCreds(ctx, id, func(ctx context.Context, creds *vaultCreds) error {
			return p.conflictRetrier.Do(ctx, "reactivate secrets", func(ctx context.Context) error {
				for _, key := range creds.secrets {
					inErr := p.activateSecret(ctx, key, id)
					if inErr != nil {
						return fmt.Errorf("cannot renew Vault secret %s: %w", key, inErr)
					}
				}

				return nil
			})
		})
		if err != nil {
			return fmt.Errorf("cannot reestablish credentials %s/%s/%s: %w", id.Type, id.Config, id.Role, err)
		}
	}

	if retiredClient != nil {
		go p.revokeVault(ctx, retiredClient)
	}

	return nil
}

func (p *vault) login(ctx context.Context) error {
	log.Info(ctx, "Logging in to Vault")

	switch {
	case p.credsCfg.Token != "":
		log.Debug(ctx, "Using provided token")
		token := strings.TrimSpace(p.credsCfg.Token)
		if token == "" {
			return errors.New("empty token")
		}

		p.vaultClient.SetToken(token)
		err := p.retrier.Do(ctx, "look up token", func(ctx context.Context) error {
			var inErr error
			p.vaultSecret, inErr = p.vaultClient.Auth().Token().LookupSelfWithContext(ctx)
			return inErr
		})
		if err != nil {
			return fmt.Errorf("cannot look up token: %w", err)
		}

		return nil

	case p.credsCfg.TokenFile != "":
		log.Debug(ctx, "Using provided token")
		t, err := os.ReadFile(p.credsCfg.TokenFile)
		if err != nil {
			return fmt.Errorf("cannot read token file %s: %w", p.credsCfg.TokenFile, err)
		}
		token := strings.TrimSpace(string(t))
		if token == "" {
			return errors.New("empty token")
		}

		p.vaultClient.SetToken(token)
		err = p.retrier.Do(ctx, "look up token", func(ctx context.Context) error {
			var inErr error
			p.vaultSecret, inErr = p.vaultClient.Auth().Token().LookupSelfWithContext(ctx)
			return inErr
		})
		if err != nil {
			return fmt.Errorf("cannot look up token: %w", err)
		}

		return nil

	case p.credsCfg.RoleID != "" && p.credsCfg.SecretID != "":
		log.Debug(ctx, "Using AppRole")
		appRole, err := approle.NewAppRoleAuth(p.credsCfg.RoleID, &approle.SecretID{
			FromString: p.credsCfg.SecretID,
		})
		if err != nil {
			return fmt.Errorf("cannot create AppRole: %w", err)
		}

		err = p.retrier.Do(ctx, "log in", func(ctx context.Context) error {
			var inErr error
			p.vaultSecret, inErr = p.vaultClient.Auth().Login(ctx, appRole)
			return inErr
		})
		if err != nil {
			return fmt.Errorf("cannot login using AppRole: %w", err)
		}

		p.ownToken = true

		return nil

	case p.credsCfg.JWT != "" && p.credsCfg.JWTMountPath != "" && p.credsCfg.JWTRole != "":
		log.Debug(ctx, "Using JWT")
		jwt := strings.TrimSpace(p.credsCfg.JWT)
		if jwt == "" {
			return errors.New("empty JWT")
		}

		err := p.retrier.Do(ctx, "log in", func(ctx context.Context) error {
			var inErr error
			mountPath := fmt.Sprintf("auth/%s/login", p.credsCfg.JWTMountPath)
			p.vaultSecret, inErr = p.vaultClient.Logical().WriteWithContext(ctx, mountPath, map[string]any{
				"role": p.credsCfg.JWTRole,
				"jwt":  jwt,
			})
			return inErr
		})
		if err != nil {
			return fmt.Errorf("cannot login using JWT: %w", err)
		}
		if p.vaultSecret == nil || p.vaultSecret.Auth == nil {
			return errors.New("cannot login using JWT: missing authentication information")
		}

		p.vaultClient.SetToken(p.vaultSecret.Auth.ClientToken)
		p.ownToken = true

		return nil

	default:
		return errors.New("missing Vault credentials")
	}
}

func (p *vault) deliverCreds(ctx context.Context, id CredsID, reactivate func(ctx context.Context, creds *vaultCreds) error) error {
	ctx = log.WithValues(ctx, "creds", id.Type+"/"+id.Config+"/"+id.Role)

	var creds *vaultCreds
	var ok bool
	func() {
		p.loginMtx.Lock()
		defer p.loginMtx.Unlock()

		creds, ok = p.activeCreds[id]
	}()
	if !ok {
		return nil
	}

	creds.applyMtx.Lock()
	defer creds.applyMtx.Unlock()

	var proceed bool
	func() {
		p.loginMtx.Lock()
		defer p.loginMtx.Unlock()

		var currentCreds *vaultCreds
		currentCreds, ok = p.activeCreds[id]
		proceed = ok && currentCreds == creds && creds.acquired
	}()
	if !proceed {
		return nil
	}

	if reactivate != nil {
		err := reactivate(ctx, creds)
		if err != nil {
			return err
		}
	}

	var credsData map[string]any
	err := func() error {
		p.loginMtx.Lock()
		defer p.loginMtx.Unlock()

		var inErr error
		credsData, inErr = p.assembleCredsData(creds.secrets)
		return inErr
	}()
	if err != nil {
		return err
	}

	err = creds.apply(ctx, credsData)
	if err != nil {
		return fmt.Errorf("cannot apply credentials: %w", err)
	}

	return nil
}

func (p *vault) Stop() error {
	p.closeMtx.Lock()
	defer p.closeMtx.Unlock()

	if p.closed {
		return nil
	}
	close(p.closeCh)
	p.closed = true

	var err error
	if p.maintainExec != nil {
		err = p.maintainExec.Wait()
	}

	var ownToken bool
	func() {
		p.loginMtx.Lock()
		defer p.loginMtx.Unlock()

		for key, secret := range p.activeSecrets {
			p.deactivateSecret(key, secret)
		}

		ownToken = p.ownToken
	}()

	if ownToken {
		p.revokeVault(context.Background(), p.vaultClient)
	}

	if err != nil {
		return fmt.Errorf("error encountered while renewing credentials: %w", err)
	}

	return nil
}

func (*vault) revokeVault(ctx context.Context, client *api.Client) {
	log.Debug(ctx, "Revoking Vault secret")

	_ = client.Auth().Token().RevokeSelfWithContext(context.WithoutCancel(ctx), "")
}

func (*vault) Type() string {
	return "Vault"
}

func (p *vault) AcquireCreds(ctx context.Context, id CredsID, apply ApplyCredsFunc) error {
	err := p.ensureNoError()
	if err != nil {
		return err
	}

	ctx = log.WithValues(ctx, "creds", id.Type+"/"+id.Config+"/"+id.Role)

	keys := p.secretKeys(id)
	if len(keys) == 0 {
		return fmt.Errorf("unsupported credentials type %q", id.Type)
	}

	var creds *vaultCreds
	func() {
		p.loginMtx.Lock()
		defer p.loginMtx.Unlock()

		var ok bool
		creds, ok = p.activeCreds[id]
		if !ok {
			creds = &vaultCreds{}
			p.activeCreds[id] = creds
		}
	}()

	creds.applyMtx.Lock()
	defer creds.applyMtx.Unlock()

	var success bool
	defer func() {
		if success {
			return
		}

		p.loginMtx.Lock()
		defer p.loginMtx.Unlock()

		p.releaseSecrets(ctx, id, creds, keys)
	}()

	var credsData map[string]any
	var proceed bool
	err = p.conflictRetrier.Do(ctx, "acquire credentials", func(ctx context.Context) error {
		var startGen uint64
		func() {
			p.loginMtx.Lock()
			defer p.loginMtx.Unlock()

			startGen = p.loginGeneration
		}()

		for _, key := range keys {
			inErr := p.activateSecret(ctx, key, id)
			if inErr != nil {
				return fmt.Errorf("cannot acquire Vault secret %s: %w", key, inErr)
			}
		}

		p.loginMtx.Lock()
		defer p.loginMtx.Unlock()

		currentCreds, ok := p.activeCreds[id]
		if !ok || currentCreds != creds {
			return nil
		}

		if p.loginGeneration != startGen {
			return &guard.ConflictError{}
		}

		creds.secrets = keys
		creds.acquired = true
		creds.apply = apply

		var inErr error
		credsData, inErr = p.assembleCredsData(keys)
		if inErr != nil {
			return inErr
		}

		proceed = true

		return nil
	})
	if err != nil {
		return err
	}
	if !proceed {
		return nil
	}

	err = creds.apply(ctx, credsData)
	if err != nil {
		return fmt.Errorf("cannot apply credentials: %w", err)
	}

	success = true

	return nil
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
	case "Azure":
		return []string{
			fmt.Sprintf("se-azure-%s/config", id.Config),
			fmt.Sprintf("se-azure-%s/creds/glci", id.Config),
		}
	case "Azure_storage":
		return []string{
			fmt.Sprintf("se-azure_storage-%s/data/application", id.Config),
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
	case "OCI_userpass":
		return []string{
			fmt.Sprintf("se-oci-%s/data/application", id.Config),
		}
	case "OpenStack":
		return []string{
			fmt.Sprintf("se-sci-%s-old/data/creds", id.Config),
		}
	default:
		return nil
	}
}

func (p *vault) activateSecret(ctx context.Context, key string, id CredsID) error {
	ctx = log.WithValues(ctx, "vaultKey", key)

	var startGen uint64
	var secret *vaultSecret
	func() {
		p.loginMtx.Lock()
		defer p.loginMtx.Unlock()

		startGen = p.loginGeneration
		var ok bool
		secret, ok = p.activeSecrets[key]
		if !ok {
			secret = &vaultSecret{}
			p.activeSecrets[key] = secret
		}
	}()

	secret.secretMtx.Lock()
	defer secret.secretMtx.Unlock()

	if secret.secret != nil {
		p.loginMtx.Lock()
		defer p.loginMtx.Unlock()

		if p.activeSecrets[key] != secret {
			return &guard.ConflictError{}
		}

		if !slices.Contains(secret.owners, id) {
			secret.owners = append(secret.owners, id)
		}

		return nil
	}

	s, w, err := p.readSecret(ctx, key)

	p.loginMtx.Lock()
	defer p.loginMtx.Unlock()

	if p.loginGeneration != startGen || p.activeSecrets[key] != secret {
		return &guard.ConflictError{}
	}

	var success bool
	defer func() {
		if success {
			return
		}

		delete(p.activeSecrets, key)
	}()

	if err != nil {
		return err
	}

	secret.watcher = w
	secret.done = make(chan struct{})
	secret.secret = s
	secret.owners = append(secret.owners, id)

	go secret.watcher.Start()
	go p.monitor(secret.done, key, secret.watcher)

	success = true
	return nil
}

func (p *vault) readSecret(ctx context.Context, key string) (*api.Secret, *api.LifetimeWatcher, error) {
	log.Debug(ctx, "Reading Vault secret")

	var secret *api.Secret
	err := p.retrier.Do(ctx, "read secret", func(ctx context.Context) error {
		var inErr error
		secret, inErr = p.vaultClient.Logical().ReadWithContext(ctx, key)
		return inErr
	})
	if err != nil {
		return nil, nil, fmt.Errorf("cannot get secret: %w", err)
	}
	if secret == nil {
		return nil, nil, errors.New("cannot get secret: secret is nil")
	}
	if secret.Data == nil {
		return nil, nil, errors.New("cannot get secret: secret has no data")
	}

	var watcher *api.LifetimeWatcher
	watcher, err = p.vaultClient.NewLifetimeWatcher(&api.LifetimeWatcherInput{
		Secret: secret,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("cannot set up token renewal: %w", err)
	}

	return secret, watcher, nil
}

func (p *vault) monitor(done <-chan struct{}, key string, watcher *api.LifetimeWatcher) {
	for {
		select {
		case <-done:
			return

		case err := <-watcher.DoneCh():
			if errors.Is(err, api.ErrLifetimeWatcherNotRenewable) {
				return
			}

			select {
			case p.events <- vaultWatchEvent{
				key: key,
				err: err,
			}:

			case <-done:
				return
			}

		case renewal := <-watcher.RenewCh():
			select {
			case p.events <- vaultWatchEvent{
				key:    key,
				secret: renewal.Secret,
			}:

			case <-done:
				return
			}
		}
	}
}

func (p *vault) assembleCredsData(keys []string) (map[string]any, error) {
	allData := make(map[string]any)
	for _, key := range keys {
		secret, ok := p.activeSecrets[key]
		if !ok || secret.secret == nil {
			return nil, fmt.Errorf("inconsistent internal state for secret %s: secret not active", key)
		}

		var secretData map[string]any
		secretData, ok = secret.secret.Data["data"].(map[string]any)
		if !ok {
			secretData = secret.secret.Data
		}
		maps.Copy(allData, secretData)
	}

	return allData, nil
}

func (p *vault) ReleaseCreds(ctx context.Context, id CredsID) {
	err := p.ensureNoError()
	if err != nil {
		return
	}

	var creds *vaultCreds
	var ok bool
	func() {
		p.loginMtx.Lock()
		defer p.loginMtx.Unlock()

		creds, ok = p.activeCreds[id]
		if ok {
			creds.acquired = false
		}
	}()
	if !ok {
		return
	}

	creds.applyMtx.Lock()
	defer creds.applyMtx.Unlock()

	p.loginMtx.Lock()
	defer p.loginMtx.Unlock()

	var currentCreds *vaultCreds
	currentCreds, ok = p.activeCreds[id]
	if !ok || currentCreds != creds {
		return
	}

	p.releaseSecrets(ctx, id, creds, creds.secrets)
}

func (p *vault) releaseSecrets(ctx context.Context, id CredsID, creds *vaultCreds, keys []string) {
	var leaseIDs []string
	for _, key := range keys {
		leaseID := p.releaseSecret(key, id)
		if leaseID != "" {
			leaseIDs = append(leaseIDs, leaseID)
		}
	}

	if p.activeCreds[id] == creds {
		delete(p.activeCreds, id)
	}

	for _, leaseID := range leaseIDs {
		go p.revokeSecret(ctx, leaseID)
	}
}

func (p *vault) releaseSecret(key string, owner CredsID) string {
	secret, ok := p.activeSecrets[key]
	if !ok {
		return ""
	}

	for i, o := range secret.owners {
		if o == owner {
			if len(secret.owners) == 1 {
				var leaseID string
				if secret.secret != nil {
					leaseID = secret.secret.LeaseID
				}

				p.deactivateSecret(key, secret)

				return leaseID
			}

			secret.owners = slices.Delete(secret.owners, i, i+1)

			return ""
		}
	}

	return ""
}

func (p *vault) deactivateSecret(key string, secret *vaultSecret) {
	if secret.done != nil {
		close(secret.done)
	}
	if secret.watcher != nil {
		secret.watcher.Stop()
	}

	delete(p.activeSecrets, key)
}

func (p *vault) revokeSecret(ctx context.Context, leaseID string) {
	log.Debug(ctx, "Revoking Vault secret", "leaseID", leaseID)

	_ = p.vaultClient.Sys().RevokeWithContext(context.WithoutCancel(ctx), leaseID)
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
