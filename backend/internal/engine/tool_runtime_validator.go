package engine

import (
	"github.com/gshark/sentinel/backend/internal/tool"
)

// ValidateExecutablePath validates that path is an acceptable external binary.
// An empty path is considered valid (meaning "use default / unset").
// expectedNames are acceptable basenames without extension (case-insensitive).
// extraAllowedDirs may be supplied by tests to permit additional directories.
func ValidateExecutablePath(path string, expectedNames []string, extraAllowedDirs ...string) error {
	v := tool.NewExecutableValidator(expectedNames, extraAllowedDirs, tool.ModeStrict)
	_, err := v.Validate(path)
	return err
}

// ValidateExecutablePathWithWarning validates the path but treats "outside
// allowed directories" as a warning instead of an error. It returns a non-empty
// warning string when the binary is otherwise valid but not in a trusted
// directory. Hard security problems still return an error.
func ValidateExecutablePathWithWarning(path string, expectedNames []string, extraAllowedDirs ...string) (warning string, err error) {
	v := tool.NewExecutableValidator(expectedNames, extraAllowedDirs, tool.ModeWarn)
	return v.Validate(path)
}
