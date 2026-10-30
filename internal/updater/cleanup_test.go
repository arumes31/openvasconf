package updater

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestComposePrunesOnlyUnusedGreenboneImages(t *testing.T) {
	executor := &recordingExecutor{}
	compose, err := NewCompose(executor, "/deployment/greenbone-compose.yaml", "greenbone", "/backups")
	if err != nil {
		t.Fatal(err)
	}
	if err := compose.PruneImages(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(executor.calls) == 0 {
		t.Fatal("no cleanup commands")
	}
	for _, command := range executor.calls {
		if len(command) != 6 || command[1] != "image" || command[2] != "prune" || command[3] != "--force" {
			t.Fatalf("unsafe cleanup command: %q", command)
		}
		for _, argument := range command {
			if argument == "--all" || argument == "--volumes" || argument == "-a" {
				t.Fatalf("overbroad cleanup: %q", command)
			}
		}
		for i := 4; i < len(command); i += 2 {
			if command[i] != "--filter" || !strings.HasPrefix(command[i+1], "label=org.opencontainers.image.source=https://github.com/greenbone/") {
				t.Fatalf("unscoped cleanup: %q", command)
			}
		}
	}
	executor.outputErr = errors.New("cleanup unavailable")
	if err := compose.PruneImages(t.Context()); err == nil {
		t.Fatal("missing cleanup error")
	}
}

type cleanupRuntime struct {
	*fakeRuntime
	pruned bool
	fail   bool
}

func (r *cleanupRuntime) PruneImages(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruned = true
	if r.fail {
		return errors.New("prune failed")
	}
	return nil
}

func TestControllerImageCleanupFollowsVerification(t *testing.T) {
	for _, kind := range []Kind{KindFeed, KindStack} {
		for _, fail := range []bool{false, true} {
			t.Run(string(kind)+"/cleanup-failure="+strconv.FormatBool(fail), func(t *testing.T) {
				runtime := &cleanupRuntime{fakeRuntime: &fakeRuntime{}, fail: fail}
				controller := newTestController(t, runtime, &fakeScanner{}, time.Now)
				op, err := controller.Trigger(t.Context(), kind, TriggerRequest{IdempotencyKey: "cleanup", Trigger: TriggerAdmin})
				if err != nil {
					t.Fatal(err)
				}
				finished := waitForTerminal(t, controller, op.ID)
				runtime.mu.Lock()
				pruned := runtime.pruned
				runtime.mu.Unlock()
				if !pruned {
					t.Fatal("successful update did not clean images")
				}
				if finished.State != StateSucceeded {
					t.Fatalf("cleanup failure changed update result to %s", finished.State)
				}
			})
		}
	}
}

func TestControllerCleansVerifiedChangesButKeepsRollbackImages(t *testing.T) {
	for _, kind := range []Kind{KindFeed, KindStack} {
		for _, failVerification := range []bool{false, true} {
			if kind == KindFeed && failVerification {
				continue
			}
			t.Run(string(kind)+"/verification-failure="+strconv.FormatBool(failVerification), func(t *testing.T) {
				base := &fakeRuntime{before: []Image{{Service: "gvmd", ID: testImageID}}, after: []Image{{Service: "gvmd", ID: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}
				runtime := &cleanupRuntime{fakeRuntime: base}
				scanner := &fakeScanner{runtime: base, failApplied: failVerification, beforeFeed: Feed{Name: "NVT", Version: "1"}, afterFeed: Feed{Name: "NVT", Version: "2"}}
				controller := newTestController(t, runtime, scanner, time.Now)
				op, err := controller.Trigger(t.Context(), kind, TriggerRequest{IdempotencyKey: "changed-cleanup", Trigger: TriggerAdmin})
				if err != nil {
					t.Fatal(err)
				}
				finished := waitForTerminal(t, controller, op.ID)
				runtime.mu.Lock()
				pruned := runtime.pruned
				runtime.mu.Unlock()
				if failVerification {
					if pruned || finished.State != StateRolledBack {
						t.Fatalf("failed verification: cleanup=%t state=%s", pruned, finished.State)
					}
				} else if !pruned || finished.State != StateSucceeded {
					t.Fatalf("verified update: cleanup=%t state=%s", pruned, finished.State)
				}
			})
		}
	}
}
