package guard

import (
	"context"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"math/rand/v2"
	"time"

	"github.com/gardenlinux/glci/internal/log"
)

const (
	// Retries is the number of times every operation is retried after its initial attempt before failing.
	Retries = 7

	// RetryBaseDelay is the initial backoff delay before the first retry.
	RetryBaseDelay = time.Second

	// RetryMaxDelay is the maximum backoff delay between retries.
	RetryMaxDelay = time.Second * 49

	// Timeout is the maximum time a single operation may take before it is considered hung.
	Timeout = time.Second * 49

	retryJitter = time.Second * 3
)

//nolint:gochecknoglobals // Cached CRC table for content integrity checks.
var crcTable = crc32.MakeTable(crc32.Castagnoli)

// RetryPolicy decides how failed operations are retried.
type RetryPolicy interface {
	Begin() RetryDecider
}

// RetryDecider decides whether to retry a failed operation and if yes how long to pause first.
type RetryDecider interface {
	NextRetry(err error) (time.Duration, bool)
}

// TimeoutPolicy decides how long an operation may run before it is considered hung.
type TimeoutPolicy interface {
	Timeout() time.Duration
}

// Retrier retries failed operations under a fixed RetryPolicy, bounding each operation under a fixed TimeoutPolicy.
type Retrier struct {
	retryPolicy   RetryPolicy
	timeoutPolicy TimeoutPolicy
}

// NewRetrier creates a Retrier using the given retry and timeout policies.
func NewRetrier(retryPolicy RetryPolicy, timeoutPolicy TimeoutPolicy) Retrier {
	return Retrier{
		retryPolicy:   retryPolicy,
		timeoutPolicy: timeoutPolicy,
	}
}

// Do runs an operation until it succeeds or the Retrier's policy gives up.
func (r Retrier) Do(ctx context.Context, operation string, run func(context.Context) error) error {
	decider := r.retryPolicy.Begin()

	var err error
	var retry int
	for {
		ctxErr := ctx.Err()
		if ctxErr != nil {
			return ctxErr
		}

		err = r.run(ctx, run)
		if err == nil {
			return nil
		}

		var proceed bool
		proceed, ctxErr = r.decideAndWait(ctx, decider, err)
		if ctxErr != nil {
			return ctxErr
		}
		if !proceed {
			return err
		}

		retry++
		log.Debug(ctx, "Operation failed, retrying", "operation", operation, "attempt", retry)
	}
}

func (r Retrier) run(ctx context.Context, run func(context.Context) error) error {
	timeout := r.timeoutPolicy.Timeout()

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	return run(ctx)
}

func (Retrier) decideAndWait(ctx context.Context, decider RetryDecider, err error) (bool, error) {
	pause, shouldRetry := decider.NextRetry(err)
	if !shouldRetry {
		return false, nil
	}

	timer := time.NewTimer(pause)
	select {
	case <-ctx.Done():
		return false, ctx.Err()

	case <-timer.C:
	}

	return true, nil
}

// CountingRetryPolicy retries a fixed number of times with an exponentially growing pause and a constant decorrelation jitter.
type CountingRetryPolicy struct{}

// Begin starts a bounded sequence of exponentially backed off retries.
func (CountingRetryPolicy) Begin() RetryDecider {
	return &countingRetryDecider{}
}

type countingRetryDecider struct {
	retry int
}

// NextRetry returns an exponentially growing pause with a constant decorrelation jitter until the retry budget is exhausted.
func (d *countingRetryDecider) NextRetry(_ error) (time.Duration, bool) {
	d.retry++

	if d.retry > Retries {
		return 0, false
	}

	backoff := RetryMaxDelay
	if d.retry <= 30 {
		backoff = RetryBaseDelay << (d.retry - 1)
	}
	backoff = min(backoff, RetryMaxDelay)

	//nolint:gosec // Jitter is decorrelation noise and is not security-sensitive, predictability is harmless.
	return max(backoff+rand.N(retryJitter*2+1)-retryJitter, RetryBaseDelay), true
}

// DelegatingRetryPolicy never retries because the underlying function performs its own retries.
type DelegatingRetryPolicy struct{}

// Begin starts a sequence that never retries because retries are delegated.
func (DelegatingRetryPolicy) Begin() RetryDecider {
	return DelegatingRetryPolicy{}
}

// NextRetry always declines because retries are delegated.
func (DelegatingRetryPolicy) NextRetry(_ error) (time.Duration, bool) {
	return 0, false
}

// GenerationalRetryPolicy retries a failed operation once per generation advance.
type GenerationalRetryPolicy struct {
	generation func() uint64
}

// NewGenerationalRetryPolicy creates a GenerationalRetryPolicy that observes generation through the given accessor.
func NewGenerationalRetryPolicy(generation func() uint64) GenerationalRetryPolicy {
	return GenerationalRetryPolicy{
		generation: generation,
	}
}

// Begin snapshots the current generation and starts a sequence of retries gated on it advancing.
func (p GenerationalRetryPolicy) Begin() RetryDecider {
	return &generationalRetryDecider{
		generation: p.generation,
		currentGen: p.generation(),
	}
}

type generationalRetryDecider struct {
	generation func() uint64
	currentGen uint64
}

// NextRetry retries immediately if the generation has advanced since the last attempt, otherwise declines.
func (d *generationalRetryDecider) NextRetry(_ error) (time.Duration, bool) {
	gen := d.generation()
	if gen == d.currentGen {
		return 0, false
	}

	d.currentGen = gen

	return RetryBaseDelay, true
}

// ConflictError is a failure caused by an operation observeing a state different from the one it expected.
type ConflictError struct{}

func (*ConflictError) Error() string {
	return "conflicting concurrent modification"
}

// ConflictAwarePolicy retries a ConflictError immediately and delegates every other failure to a wrapped policy.
type ConflictAwarePolicy struct {
	policy RetryPolicy
}

// NewConflictAwarePolicy creates a ConflictAwarePolicy that that retries conflicts and delegates other failures to the wrapped policy.
func NewConflictAwarePolicy(policy RetryPolicy) ConflictAwarePolicy {
	return ConflictAwarePolicy{
		policy: policy,
	}
}

// Begin starts a sequence that retries conflicts immediately and delegates other failures to the wrapped policy.
func (p ConflictAwarePolicy) Begin() RetryDecider {
	return &conflictAwareDecider{
		decider: p.policy.Begin(),
	}
}

type conflictAwareDecider struct {
	decider RetryDecider
}

// NextRetry retries immediately on a ConflictError and delegates the decision to the wrapped policy otherwise.
func (d *conflictAwareDecider) NextRetry(err error) (time.Duration, bool) {
	_, ok := errors.AsType[*ConflictError](err)
	if ok {
		return RetryBaseDelay, true
	}

	return d.decider.NextRetry(err)
}

// DelegatingTimeoutPolicy never bounds an operation because the underlying function enforces its own timeouts.
type DelegatingTimeoutPolicy struct{}

// Timeout returns no timeout because timeouts are delegated.
func (DelegatingTimeoutPolicy) Timeout() time.Duration {
	return 0
}

// BoundedTimeoutPolicy bounds every operation by Timeout.
type BoundedTimeoutPolicy struct{}

// Timeout bounds an operation by Timeout.
func (BoundedTimeoutPolicy) Timeout() time.Duration {
	return Timeout
}

// CustomTimeoutPolicy bounds every operation by a given fixed timeout.
type CustomTimeoutPolicy struct {
	timeout time.Duration
}

// NewCustomTimeoutPolicy creates a CustomTimeoutPolicy that bounds every operation by the given timeout.
func NewCustomTimeoutPolicy(timeout time.Duration) CustomTimeoutPolicy {
	return CustomTimeoutPolicy{
		timeout: timeout,
	}
}

// Timeout bounds an operation by the given timeout.
func (p CustomTimeoutPolicy) Timeout() time.Duration {
	return p.timeout
}

// ContentSource is a source that Content can be opened from.
type ContentSource interface {
	Open(ctx context.Context, offset int64, identity string) (Content, error)
}

// Content is readable content that can be reopened.
type Content struct {
	io.ReadCloser

	Identity  string
	Size      int64
	CanResume bool
}

// NewRetryingReader opens Content from a source and returns a self-healing seekable reader over it.
func NewRetryingReader(ctx context.Context, retrier Retrier, source ContentSource) (io.ReadSeekCloser, error) {
	r := &retryingReader{
		retrier: retrier,
		source:  source,
		ctx:     ctx,
	}

	err := r.open(0)
	if err != nil {
		return nil, err
	}

	return r, nil
}

type retryingReader struct {
	retrier Retrier
	source  ContentSource
	ctx     context.Context //nolint:containedctx // Read carries no context, so reopens reuse the one from NewRetryingReader.

	content        Content
	offset         int64
	readErr        error
	opened         bool
	prefixChecksum hash.Hash32
}

type prefixChangedError struct{}

func (*prefixChangedError) Error() string {
	return "content changed under read"
}

func (r *retryingReader) Read(p []byte) (int, error) {
	if r.content.ReadCloser == nil {
		return 0, errors.New("cannot read from closed content")
	}

	decider := r.retrier.retryPolicy.Begin()

	var retry int
	for {
		if r.readErr != nil {
			_, ok := errors.AsType[*prefixChangedError](r.readErr)
			if r.content.Identity == "" || ok {
				return 0, fmt.Errorf("cannot read content: %w", r.readErr)
			}

			proceed, ctxErr := r.retrier.decideAndWait(r.ctx, decider, r.readErr)
			if ctxErr != nil {
				return 0, ctxErr
			}
			if !proceed {
				return 0, fmt.Errorf("cannot read content: %w", r.readErr)
			}

			retry++
			log.Debug(r.ctx, "Content read failed, retrying", "offset", r.offset, "retry", retry)

			r.readErr = r.open(r.offset)
			if r.readErr != nil {
				continue
			}
		}

		n, err := r.read(p)
		r.offset += int64(n)
		if n > 0 && !r.content.CanResume {
			_, _ = r.prefixChecksum.Write(p[:n])
		}
		if err == nil || errors.Is(err, io.EOF) {
			return n, err
		}

		r.readErr = err
		if n > 0 {
			return n, nil
		}
	}
}

func (r *retryingReader) read(p []byte) (int, error) {
	reader := r.content.ReadCloser
	timer := time.AfterFunc(Timeout, func() {
		_ = reader.Close()
	})

	n, err := r.content.Read(p)

	if !timer.Stop() {
		r.content.ReadCloser = nil

		return 0, errors.New("timed out")
	}

	return n, err
}

func (r *retryingReader) Seek(offset int64, whence int) (int64, error) {
	var target int64
	switch whence {
	case io.SeekStart:
		target = offset

	case io.SeekCurrent:
		target = r.offset + offset

	case io.SeekEnd:
		if r.content.Size < 0 {
			return 0, errors.New("cannot seek from the end of content of unknown size")
		}
		target = r.content.Size + offset

	default:
		return 0, errors.New("invalid whence")
	}
	if target < 0 {
		return 0, fmt.Errorf("cannot seek to negative position %d", target)
	}

	if target == r.offset {
		return r.offset, nil
	}

	if r.content.Identity == "" {
		return 0, errors.New("cannot seek this content")
	}

	if r.content.Size >= 0 && target >= r.content.Size {
		if r.content.ReadCloser != nil {
			_ = r.content.Close()
		}
		r.content.ReadCloser = eofReadCloser{}
		r.offset = target
		r.readErr = nil

		return target, nil
	}

	err := r.open(target)
	if err != nil {
		return 0, err
	}
	r.readErr = nil

	return target, nil
}

type eofReadCloser struct{}

func (eofReadCloser) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (eofReadCloser) Close() error {
	return nil
}

func (r *retryingReader) open(offset int64) error {
	if r.content.ReadCloser != nil {
		_ = r.content.Close()
		r.content.ReadCloser = nil
	}

	var sourceOffset int64
	if r.content.CanResume {
		sourceOffset = offset
	}
	content, err := r.source.Open(r.ctx, sourceOffset, r.content.Identity)
	if err != nil {
		return fmt.Errorf("cannot open content: %w", err)
	}

	if !r.opened {
		r.opened = true
		r.content = content
	}
	r.content.ReadCloser = content.ReadCloser

	if !r.content.CanResume {
		if offset == 0 {
			r.prefixChecksum = crc32.New(crcTable)
		} else {
			rereadChecksum := crc32.New(crcTable)
			_, err = io.CopyN(rereadChecksum, r.content, offset)
			if err != nil {
				return fmt.Errorf("cannot read content: %w", err)
			}

			if offset == r.offset && rereadChecksum.Sum32() != r.prefixChecksum.Sum32() {
				return &prefixChangedError{}
			}

			r.prefixChecksum = rereadChecksum
		}
	}
	r.offset = offset

	return nil
}

func (r *retryingReader) Close() error {
	if r.content.ReadCloser == nil {
		return nil
	}

	err := r.content.Close()
	r.content.ReadCloser = nil
	if err != nil {
		return fmt.Errorf("cannot close content: %w", err)
	}

	return nil
}
