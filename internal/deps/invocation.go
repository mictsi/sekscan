package deps

import "sekscan/internal/config"

// InvocationArgs expands only configured portable arguments. Executables must be
// resolved and verified before invocation; this method does not run a shell.
func (m *Manager) InvocationArgs(name string, t config.Tool, args []string) ([]string, error) {
	return m.CommandArgs(name, t, args), nil
}
