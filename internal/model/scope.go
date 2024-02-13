package model

import (
	"errors"
	"strings"
)

type ScopeInfo interface {
	GetName() string
	IsDefault() bool
}

type Scope struct {
	Name    string
	Default bool
}

func (s *Scope) GetName() string {
	return s.Name
}

func (s *Scope) IsDefault() bool {
	return s.Default
}

func (s *Scope) String() string {
	return s.Name
}

var (
	Profile ScopeInfo = &Scope{
		Name:    "profile",
		Default: true,
	}
	Avatar ScopeInfo = &Scope{
		Name:    "avatar",
		Default: false,
	}
	allScopes     = []ScopeInfo{Profile, Avatar}
	defaultScopes = []ScopeInfo{Profile}
)

func ParseScope(s string) (ScopeInfo, error) {
	for _, scope := range allScopes {
		if s == scope.GetName() {
			return scope, nil
		}
	}
	return nil, errors.New("invalid scope name")
}

func ParseScopes(s string) []ScopeInfo {
	m := map[string]ScopeInfo{}
	for _, scopeStr := range strings.Fields(s) {
		for _, scope := range allScopes {
			if scopeStr == scope.GetName() {
				m[scope.GetName()] = scope
			}
		}
	}
	for _, scope := range defaultScopes {
		if m[scope.GetName()] == nil {
			m[scope.GetName()] = scope
		}
	}
	var r []ScopeInfo
	for _, scope := range m {
		r = append(r, scope)
	}
	return r
}
