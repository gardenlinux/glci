package access

// Spec is an OCM access specification held as a concrete tagged struct and serialized by go-yaml.
type Spec any

// OCI returns the access specification for an OCI artifact at the given reference.
func OCI(ref string) Spec {
	return ociImage{
		Type:           "ociImage",
		ImageReference: ref,
	}
}

//nolint:tagliatelle // Defined by OCM.
type ociImage struct {
	Type           string `yaml:"type"`
	ImageReference string `yaml:"imageReference"`
}

// S3 returns the access specification for an object in an S3 bucket.
func S3(bucket, key string) Spec {
	return s3{
		Type:   "s3",
		Bucket: bucket,
		Key:    key,
	}
}

type s3 struct {
	Type   string `yaml:"type"`
	Bucket string `yaml:"bucket"`
	Key    string `yaml:"key"`
}
