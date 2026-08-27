package updater

import (
	"bytes"
	"context"
	"io"
	"testing"
)

type recordingExecutor struct {
	calls  [][]string
	output []byte
}

func (e *recordingExecutor) Output(_ context.Context, args ...string) ([]byte, error) {
	e.calls = append(e.calls, append([]string{"docker"}, args...))
	return e.output, nil
}

func (*recordingExecutor) OutputTo(context.Context, io.Writer, ...string) error  { return nil }
func (*recordingExecutor) InputFrom(context.Context, io.Reader, ...string) error { return nil }

func TestComposePullFeedUsesOnlyFixedArguments(t *testing.T) {
	executor := &recordingExecutor{}
	compose, err := NewCompose(executor, "/deployment/greenbone-compose.yaml", "greenbone-community-edition", "/backups")
	if err != nil {
		t.Fatal(err)
	}
	if err := compose.PullFeed(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(executor.calls) != 1 {
		t.Fatalf("command count = %d, want 1", len(executor.calls))
	}
	want := []string{
		"docker", "compose", "--project-name", "greenbone-community-edition",
		"--file", "/deployment/greenbone-compose.yaml", "pull", "--quiet",
		"notus-data", "vulnerability-tests", "scap-data", "dfn-cert-data",
		"cert-bund-data", "report-formats", "data-objects",
	}
	if !equalStrings(executor.calls[0], want) {
		t.Fatalf("command = %#v, want %#v", executor.calls[0], want)
	}
}

func TestDecodeImagesAcceptsArrayAndJSONLines(t *testing.T) {
	array := []byte(`[{"ID":"sha256:a","Repository":"registry.community.greenbone.net/community/gvmd","Service":"gvmd","Tag":"stable"}]`)
	lines := bytes.ReplaceAll(array[1:len(array)-1], []byte("},{"), []byte("}\n{"))
	for _, input := range [][]byte{array, lines} {
		images, err := decodeImages(input)
		if err != nil {
			t.Fatal(err)
		}
		if len(images) != 1 || images[0].Service != "gvmd" {
			t.Fatalf("images = %#v", images)
		}
	}
}

func TestSnapshotAcceptsComposeV5ContainerName(t *testing.T) {
	executor := &recordingExecutor{output: []byte(`[{"ID":"sha256:a","ContainerName":"greenbone-community-edition-gvmd-1","Repository":"registry.community.greenbone.net/community/gvmd","Tag":"stable"}]`)}
	compose, err := NewCompose(
		executor,
		"/deployment/greenbone-compose.yaml",
		"greenbone-community-edition",
		"/backups",
	)
	if err != nil {
		t.Fatal(err)
	}
	images, err := compose.Snapshot(t.Context(), []string{"gvmd"})
	if err != nil {
		t.Fatal(err)
	}
	if len(images) != 1 || images[0].Service != "gvmd" {
		t.Fatalf("images = %#v", images)
	}
}

func TestSnapshotRejectsUnexpectedContainerName(t *testing.T) {
	executor := &recordingExecutor{output: []byte(`[{"ID":"sha256:a","ContainerName":"other-gvmd-1","Repository":"registry.community.greenbone.net/community/gvmd","Tag":"stable"}]`)}
	compose, err := NewCompose(
		executor,
		"/deployment/greenbone-compose.yaml",
		"greenbone-community-edition",
		"/backups",
	)
	if err != nil {
		t.Fatal(err)
	}
	images, err := compose.Snapshot(t.Context(), []string{"gvmd"})
	if err != nil {
		t.Fatal(err)
	}
	if len(images) != 0 {
		t.Fatalf("images = %#v, want none", images)
	}
}

func TestComposeRejectsUnallowlistedServiceAndImage(t *testing.T) {
	compose, err := NewCompose(&recordingExecutor{}, "/deployment/greenbone-compose.yaml", "greenbone-community-edition", "/backups")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compose.Snapshot(t.Context(), []string{"openvasconf"}); err == nil {
		t.Fatal("Snapshot(openvasconf) error = nil, want allowlist rejection")
	}
	if err := compose.validateImage(Image{
		Service: "gvmd", Repository: "docker.io/untrusted/gvmd", Tag: "latest", ID: testImageID,
	}); err == nil {
		t.Fatal("validateImage(untrusted) error = nil, want registry rejection")
	}
}

func TestStackServicesExcludeApplicationAndCredentialInitialization(t *testing.T) {
	compose, err := NewCompose(
		&recordingExecutor{},
		"/deployment/greenbone-compose.yaml",
		"greenbone-community-edition",
		"/backups",
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range compose.StackServices() {
		switch service {
		case "openvasconf", "openvasconf-updater", "gvmd-user-init":
			t.Fatalf("unsafe service %q included in automated stack upgrades", service)
		}
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
