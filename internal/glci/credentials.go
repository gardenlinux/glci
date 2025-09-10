package glci

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"

	"github.com/gardenlinux/glci/internal/log"
)

// Credentials is a mapping from a key to an opaque data type, different for each implementation.
type Credentials map[string]any

// LoadCredentials parses either a YAML file or a Base64-encoded YAML containing credentials.
func LoadCredentials(ctx context.Context, credsFile, credsYamlBase64 string) (Credentials, error) {
	var credsYAML []byte
	var err error

	if credsYamlBase64 != "" {
		log.Debug(ctx, "Loading credentials from Base64")
		credsYAML, err = base64.StdEncoding.DecodeString(credsYamlBase64)
		if err != nil {
			return nil, fmt.Errorf("invalid credentials: %w", err)
		}
	} else if credsFile != "" {
		log.Debug(ctx, "Loading credentials from file", "file", credsFile)
		credsYAML, err = os.ReadFile(filepath.Clean(credsFile))
		if err != nil {
			return nil, fmt.Errorf("cannot read credentials file: %w", err)
		}
	}

	var creds map[string]any
	err = yaml.Unmarshal(credsYAML, &creds)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials YAML: %w", err)
	}

	return creds, nil
}
