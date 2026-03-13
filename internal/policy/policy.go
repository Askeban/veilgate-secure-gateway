package policy

import (
	"encoding/json"
	"os"
	"strings"
)

// Engine defines the interface for policy decisions
type Engine interface {
	// AllowTool checks if a role is allowed to use a tool
	AllowTool(role, tool string) bool
	// AllowFunction checks if a role is allowed to use a specific function
	AllowFunction(role, function string) bool
	// GetRole returns the role for a given API key
	GetRole(apiKey string) string
}

// LocalPolicy implements Engine using a local JSON file (same format as PoC)
type LocalPolicy struct {
	Bindings map[string]map[string]string `json:"bindings"` // api_keys -> key:role
	Roles    map[string]Role              `json:"roles"`
}

type Role struct {
	AllowTools    []string `json:"allow_tools"`
	DenyFunctions []string `json:"deny_functions"`
}

func NewLocalPolicy(path string) (*LocalPolicy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p LocalPolicy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *LocalPolicy) GetRole(apiKey string) string {
	if keys, ok := p.Bindings["api_keys"]; ok {
		return keys[apiKey]
	}
	return ""
}

func (p *LocalPolicy) AllowTool(role, tool string) bool {
	r, ok := p.Roles[role]
	if !ok {
		return false
	}
	for _, t := range r.AllowTools {
		if strings.EqualFold(t, tool) {
			return true
		}
	}
	return false
}

func (p *LocalPolicy) AllowFunction(role, function string) bool {
	r, ok := p.Roles[role]
	if !ok {
		return false
	}
	// Check Deny List
	for _, f := range r.DenyFunctions {
		if strings.EqualFold(f, function) {
			return false
		}
	}
	return true
}
