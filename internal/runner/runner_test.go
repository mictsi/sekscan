package runner

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("SEKSCAN_TEST_CHILD") != "1" {
		return
	}
	args := os.Args
	mode := args[len(args)-1]
	switch mode {
	case "success":
		os.Stdout.WriteString("ok")
	case "secret":
		os.Stderr.WriteString("SUPER_SECRET_VALUE")
		os.Exit(7)
	case "big":
		os.Stdout.WriteString(strings.Repeat("x", 8192))
	case "timeout":
		time.Sleep(5 * time.Second)
	}
	os.Exit(0)
}
func helperRequest(mode string) Request {
	return Request{Executable: os.Args[0], Args: []string{"-test.run=TestHelperProcess", "--", mode}, Env: append(os.Environ(), "SEKSCAN_TEST_CHILD=1"), Timeout: 2 * time.Second, MaxOutput: 1024}
}
func TestExecutionAndRedaction(t *testing.T) {
	x := OSExecutor{}
	r, e := x.Run(context.Background(), helperRequest("success"))
	if e != nil || string(r.Stdout) != "ok" {
		t.Fatal(e)
	}
	_, e = x.Run(context.Background(), helperRequest("secret"))
	if e == nil || strings.Contains(e.Error(), "SUPER_SECRET") {
		t.Fatal(e)
	}
	request := helperRequest("secret")
	request.SuccessCodes = []int{7}
	if _, e = x.Run(context.Background(), request); e != nil {
		t.Fatal(e)
	}
}
func TestOutputLimit(t *testing.T) {
	_, e := (OSExecutor{}).Run(context.Background(), helperRequest("big"))
	if e == nil {
		t.Fatal("no output limit")
	}
}
func TestTimeout(t *testing.T) {
	r := helperRequest("timeout")
	r.Timeout = 50 * time.Millisecond
	start := time.Now()
	_, e := (OSExecutor{}).Run(context.Background(), r)
	if e == nil || time.Since(start) > 2*time.Second {
		t.Fatal("timeout not enforced", e)
	}
}
func TestSanitizeEnvironment(t *testing.T) {
	t.Setenv("TRIVY_SEVERITY", "LOW")
	t.Setenv("TRIVY_PASSWORD", "credential")
	env := Environment("GRYPE_DB_AUTO_UPDATE=false")
	for _, s := range env {
		if strings.HasPrefix(s, "TRIVY_SEVERITY=") {
			t.Fatal("inherited policy")
		}
	}
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "TRIVY_PASSWORD=credential") || !strings.Contains(joined, "GRYPE_DB_AUTO_UPDATE=false") {
		t.Fatal("missing explicit credentials or settings")
	}
}

func TestExplicitSuccessCodesRejectZero(t *testing.T) {
	request := helperRequest("success")
	request.SuccessCodes = []int{7}
	if _, err := (OSExecutor{}).Run(context.Background(), request); err == nil {
		t.Fatal("ignored explicit success codes")
	}
}
