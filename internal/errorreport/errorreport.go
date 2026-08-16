package errorreport

import (
	"strings"

	"github.com/gardenlinux/glci/internal/graph"
)

// RenderedError is an error rendered as an indented tree, additionally exposing any critical errors found within it.
type RenderedError struct {
	err            string
	CriticalErrors []error
}

// Render walks an error tree, rendering it as an indented representation and collecting any critical errors within.
func Render(err error) *RenderedError {
	if err == nil {
		return &RenderedError{}
	}

	var lines []string
	var criticalErrors []error

	_ = graph.WalkTree(resolveEntry(err, 0), func(e renderEntry) ([]renderEntry, error) {
		children := make([]renderEntry, 0, len(e.childErrors))
		for _, childErr := range e.childErrors {
			if childErr == nil {
				continue
			}

			children = append(children, resolveEntry(childErr, e.childDepth))
		}

		return children, nil
	}, graph.PreOrder, func(e renderEntry, _ int) error {
		if e.line != nil {
			lines = append(lines, linePrefix(e.depth)+*e.line)
		}

		criticalErrors = append(criticalErrors, e.criticalErrors...)

		return nil
	})

	return &RenderedError{
		err:            strings.Join(lines, "\n"),
		CriticalErrors: criticalErrors,
	}
}

type renderEntry struct {
	line           *string
	depth          int
	childErrors    []error
	childDepth     int
	criticalErrors []error
}

func resolveEntry(outerErr error, depth int) renderEntry {
	type multiUnwrapper interface {
		Unwrap() []error
	}
	type unwrapper interface {
		Unwrap() error
	}

	entry := renderEntry{
		depth:      depth,
		childDepth: depth,
	}

	err := outerErr
	for {
		criticalErr, ok := err.(*criticalError) //nolint:errorlint // Intentional exact error assertion.
		if ok {
			entry.criticalErrors = append(entry.criticalErrors, criticalErr.Unwrap())
		}

		var multiErr multiUnwrapper
		multiErr, ok = err.(multiUnwrapper)
		if ok {
			header := strings.TrimRight(strings.TrimSuffix(outerErr.Error(), err.Error()), " ")
			if header != "" {
				entry.line = &header
				entry.childDepth = depth + 1
			}

			entry.childErrors = multiErr.Unwrap()

			return entry
		}

		var wrapErr unwrapper
		wrapErr, ok = err.(unwrapper)
		if ok {
			cause := wrapErr.Unwrap()
			if cause == nil {
				break
			}

			err = cause
			continue
		}

		break
	}

	line := outerErr.Error()
	entry.line = &line

	return entry
}

func linePrefix(depth int) string {
	if depth == 0 {
		return ""
	}

	return strings.Repeat("  ", depth-1) + "- "
}

func (e *RenderedError) Error() string {
	return e.err
}

// Banner renders the critical errors into a prominent block, or an empty string if there are none.
func (e *RenderedError) Banner() string {
	if len(e.CriticalErrors) == 0 {
		return ""
	}

	heavyDivider := strings.Repeat("=", 80)
	lightDivider := strings.Repeat("-", 80)

	lines := make([]string, 0, len(e.CriticalErrors)*2+2)
	lines = append(lines, criticalErrorArt, heavyDivider)
	for i, critical := range e.CriticalErrors {
		if i > 0 {
			lines = append(lines, lightDivider)
		}
		lines = append(lines, critical.Error())
	}
	lines = append(lines, heavyDivider)

	return strings.Join(lines, "\n")
}

const criticalErrorArt = `
=====:  :#:                -@-      .--         :@=                :#:  :=====
+++++-   @#               .@#   +#: .@@:   -@#   #@:               #@   -+++++
         =@.              #@.   +@%  =@@   %@*   .@%              .@+
          @*             .@%     #@+  =-  =@@     #@.             +@
          *@             -@*      .      -@@:     *@-             @*
          .@=            -@*           .*@@:      *@-            =@.
           #@            .@%         -*@@*.       #@.            @#
           :@-            #@.     .*@@@+.        .@%            -@:
            %% ---------  .@#      .=:           #@:  --------- %%
            -%:********+   -@-                  :@=   +********:%-

  ____ ____  ___ _____ ___ ____    _    _       _____ ____  ____   ___  ____
 / ___|  _ \|_ _|_   _|_ _/ ___|  / \  | |     | ____|  _ \|  _ \ / _ \|  _ \
| |   | |_) || |  | |  | | |     / _ \ | |     |  _| | |_) | |_) | | | | |_) |
| |___|  _ < | |  | |  | | |___ / ___ \| |___  | |___|  _ <|  _ <| |_| |  _ <
 \____|_| \_\___| |_| |___\____/_/   \_\_____| |_____|_| \_\_| \_\\___/|_| \_\`

type criticalError struct {
	err error
}

// MarkCritical marks an error as critical so that it is surfaced prominently at the top level.
func MarkCritical(err error) error {
	if err == nil {
		return nil
	}

	return &criticalError{
		err: err,
	}
}

func (e *criticalError) Error() string {
	return e.err.Error()
}

func (e *criticalError) Unwrap() error {
	return e.err
}
