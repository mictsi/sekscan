package scan

import (
	"fmt"
	"sekscan/internal/config"
	"sekscan/internal/store"
)

func configureInvocation(t config.Tool, args []string) ([]string, string, error) {
	out := append([]string{}, args...)
	hash := ""
	if t.NativeConfig != "" {
		if _, err := store.Read(t.NativeConfig, 4<<20); err != nil {
			return nil, "", fmt.Errorf("cannot read scanner native configuration")
		}
		var err error
		hash, err = store.SHA256(t.NativeConfig)
		if err != nil {
			return nil, "", err
		}
		replaced := false
		for i := 0; i < len(out)-1; i++ {
			if out[i] == "--config" {
				out[i+1] = t.NativeConfig
				replaced = true
				break
			}
		}
		if !replaced {
			return nil, "", fmt.Errorf("scanner invocation has no native configuration slot")
		}
	}
	if len(t.ExtraArgs) > 0 {
		i := len(out)
		for n, a := range out {
			if a == "--" {
				i = n
				break
			}
		}
		tail := append([]string{}, out[i:]...)
		out = append(out[:i], t.ExtraArgs...)
		out = append(out, tail...)
	}
	return out, hash, nil
}
