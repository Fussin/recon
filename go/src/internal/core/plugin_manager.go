package core

import "github.com/autonomouspen/autonomouspen-ai/internal/scanner"

// PluginManager is a struct for managing plugins.
type PluginManager struct {
	// A list of registered plugins.
	plugins []scanner.Scanner
}

// NewPluginManager creates a new PluginManager.
func NewPluginManager() (*PluginManager, error) {
	return &PluginManager{}, nil
}

// Register registers a new plugin.
func (p *PluginManager) Register(plugin scanner.Scanner) {
	p.plugins = append(p.plugins, plugin)
}

// GetPlugins returns all the registered plugins.
func (p *PluginManager) GetPlugins() []scanner.Scanner {
	return p.plugins
}
