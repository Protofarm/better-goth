package handlers

import (
	"fmt"
	"strings"

	errs "github.com/Protofarm/better-goth/internal/oauth-server/errors"
)

func normalizeScope(scope string) string {
	return strings.Join(strings.Fields(scope), " ")
}

func scopeIncludes(scope, target string) bool {
	for _, candidate := range strings.Fields(scope) {
		if candidate == target {
			return true
		}
	}
	return false
}

func validateRequestedScope(scope string, allowed []string) error {
	if scope == "" {
		return nil
	}

	allowedSet := make(map[string]struct{}, len(allowed))
	for _, candidate := range allowed {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		allowedSet[candidate] = struct{}{}
	}

	for _, requested := range strings.Fields(scope) {
		if _, ok := allowedSet[requested]; !ok {
			return fmt.Errorf("%s: %s", errs.MsgInvalidScope, requested)
		}
	}

	return nil
}

func resolveRequestedScope(requested string, allowed []string, defaultScope string) (string, error) {
	requested = normalizeScope(requested)
	if requested == "" {
		return normalizeScope(defaultScope), nil
	}

	if err := validateRequestedScope(requested, allowed); err != nil {
		return "", err
	}

	return requested, nil
}
