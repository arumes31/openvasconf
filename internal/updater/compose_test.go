package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type recordingExecutor struct {
	calls       [][]string
	output      []byte
	outputs     [][]byte
	outputErr   error
	failAt      int
	outputCalls int
	outputToErr error
	inputErr    error
	input       string
}

func (e *recordingExecutor) Output(_ context.Context, args ...string) ([]byte, error) {
	e.calls = append(e.calls, append([]string{"docker"}, args...))
	e.outputCalls++
	if e.outputErr != nil && (e.failAt == 0 || e.outputCalls == e.failAt) {
		return nil, e.outputErr
	}
	if len(e.outputs) > 0 {
		output := e.outputs[0]
		e.outputs = e.outputs[1:]
		return output, nil
	}
	return e.output, nil
}

func (e *recordingExecutor) OutputTo(_ context.Context, output io.Writer, args ...string) error {
	e.calls = append(e.calls, append([]string{"docker"}, args...))
	if e.outputToErr != nil {
		return e.outputToErr
	}
	_, err := io.WriteString(output, "database backup")
	return err
}

func (e *recordingExecutor) InputFrom(_ context.Context, input io.Reader, args ...string) error {
	e.calls = append(e.calls, append([]string{"docker"}, args...))
	contents, err := io.ReadAll(input)
	if err != nil {
		return err
	}
	e.input = string(contents)
	return e.inputErr
}

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
	feeds := compose.FeedServices()
	feeds[0] = "tampered"
	if compose.FeedServices()[0] == "tampered" {
		t.Fatal("FeedServices() returned mutable internal storage")
	}
}

func TestNewComposeAndValidationHelpers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		executor  DockerExecutor
		file      string
		project   string
		backupDir string
	}{
		{name: "missing executor", file: "/compose.yaml", project: "greenbone", backupDir: "/backups"},
		{name: "relative compose", executor: &recordingExecutor{}, file: "compose.yaml", project: "greenbone", backupDir: "/backups"},
		{name: "relative backup", executor: &recordingExecutor{}, file: "/compose.yaml", project: "greenbone", backupDir: "backups"},
		{name: "invalid project", executor: &recordingExecutor{}, file: "/compose.yaml", project: "Greenbone!", backupDir: "/backups"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewCompose(test.executor, test.file, test.project, test.backupDir); err == nil {
				t.Fatal("NewCompose() error = nil")
			}
		})
	}
	for _, project := range []string{"greenbone", "greenbone-1", "g_1"} {
		if !validProjectName(project) {
			t.Errorf("validProjectName(%q) = false", project)
		}
	}
	for _, project := range []string{"", "-greenbone", strings.Repeat("a", 64)} {
		if validProjectName(project) {
			t.Errorf("validProjectName(%q) = true", project)
		}
	}
	if got, ok := absolutePath("/deployment/../compose.yaml"); !ok || got != "/compose.yaml" {
		t.Errorf("absolutePath() = %q, %t", got, ok)
	}
	if repository, tag := splitImageReference("registry.example/team/image:stable"); repository != "registry.example/team/image" || tag != "stable" {
		t.Errorf("splitImageReference(tagged) = %q, %q", repository, tag)
	}
	if repository, tag := splitImageReference("registry.example:5000/team/image"); repository != "registry.example:5000/team/image" || tag != "latest" {
		t.Errorf("splitImageReference(untagged) = %q, %q", repository, tag)
	}
	for _, value := range []string{"operation-1", "abc123"} {
		if !validIdentifier(value) {
			t.Errorf("validIdentifier(%q) = false", value)
		}
	}
	for _, value := range []string{"", "UPPER", "has_space", strings.Repeat("a", 81)} {
		if validIdentifier(value) {
			t.Errorf("validIdentifier(%q) = true", value)
		}
	}
}

func TestLimitedBufferAndCommandFailure(t *testing.T) {
	t.Parallel()

	var buffer limitedBuffer
	input := bytes.Repeat([]byte("x"), maxCommandOutput+10)
	if written, err := buffer.Write(input); err != nil || written != len(input) {
		t.Fatalf("Write() = %d, %v", written, err)
	}
	if len(buffer.Bytes()) != maxCommandOutput || !strings.Contains(buffer.String(), "output truncated") {
		t.Errorf("limited buffer length/string = %d, %q", len(buffer.Bytes()), buffer.String()[maxCommandOutput-5:])
	}
	if written, err := buffer.Write([]byte("ignored")); err != nil || written != len("ignored") {
		t.Errorf("Write(after full) = %d, %v", written, err)
	}
	base := errors.New("exit status 1")
	if err := commandFailure(base, ""); !errors.Is(err, base) || strings.Contains(err.Error(), "stderr") {
		t.Errorf("commandFailure(empty) = %v", err)
	}
	if err := commandFailure(base, "stderr"); !strings.Contains(err.Error(), "stderr") {
		t.Errorf("commandFailure(stderr) = %v", err)
	}
}

func TestComposeValidateAndResolvedSnapshot(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	composePath := filepath.Join(directory, "compose.yaml")
	if err := os.WriteFile(composePath, []byte("services: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	services := make(map[string]map[string]string, len(stackServices))
	for _, service := range stackServices {
		services[service] = map[string]string{"image": approvedRegistryPrefix + service + ":stable"}
	}
	configuration, err := json.Marshal(map[string]any{"services": services})
	if err != nil {
		t.Fatal(err)
	}
	executor := &recordingExecutor{outputs: [][]byte{[]byte("27.0"), configuration}}
	compose, err := NewCompose(executor, composePath, "greenbone", directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := compose.Validate(t.Context()); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	executor.outputs = [][]byte{
		[]byte(`{"services":{"gvmd":{"image":"registry.community.greenbone.net/community/gvmd:stable"},"gsa":{"image":"registry.community.greenbone.net/community/gsa"}}}`),
		[]byte(`{"Id":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`),
		[]byte(`{"Id":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`),
	}
	images, err := compose.ResolvedSnapshot(t.Context(), []string{"gvmd", "gsa"})
	if err != nil {
		t.Fatalf("ResolvedSnapshot() error = %v", err)
	}
	if len(images) != 2 || images[0].Service != "gsa" || images[0].Tag != "latest" || images[1].Tag != "stable" {
		t.Errorf("resolved images = %#v", images)
	}
}

func TestComposeApplyBackupRollbackAndPrune(t *testing.T) {
	directory := t.TempDir()
	executor := &recordingExecutor{}
	compose, err := NewCompose(executor, filepath.Join(directory, "compose.yaml"), "greenbone", directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := compose.PullStack(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := compose.ApplyFeed(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := compose.ApplyStack(t.Context()); err != nil {
		t.Fatal(err)
	}
	backup, err := compose.Backup(t.Context(), "operation-1")
	if err != nil {
		t.Fatalf("Backup() error = %v", err)
	}
	if contents, err := os.ReadFile(backup); err != nil || string(contents) != "database backup" {
		t.Fatalf("backup contents = %q, %v", contents, err)
	}
	image := Image{
		Service: "gvmd", Repository: approvedRegistryPrefix + "gvmd", Tag: "stable",
		ID: "sha256:" + strings.Repeat("a", 64),
	}
	if err := compose.Rollback(t.Context(), []Image{image}, backup); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	if executor.input != "database backup" {
		t.Errorf("rollback input = %q", executor.input)
	}
	if _, err := compose.Backup(t.Context(), "INVALID"); err == nil {
		t.Fatal("Backup(invalid ID) error = nil")
	}
	if err := compose.Rollback(t.Context(), nil, filepath.Join(directory, "..", "outside.dump")); err == nil {
		t.Fatal("Rollback(outside backup) error = nil")
	}

	for _, name := range []string{"old.dump", "new.dump", "ignore.txt"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := compose.PruneBackups(1, backup); err != nil {
		t.Fatalf("PruneBackups() error = %v", err)
	}
	if err := compose.PruneBackups(10, backup); err != nil {
		t.Fatalf("PruneBackups(retain all) error = %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	dumpCount := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".dump") {
			dumpCount++
		}
	}
	if dumpCount != 2 {
		t.Errorf("retained dump count = %d, want protected + one", dumpCount)
	}
}

func TestComposeRejectsInvalidImageAndExecutorErrors(t *testing.T) {
	t.Parallel()

	compose, err := NewCompose(&recordingExecutor{}, "/compose.yaml", "greenbone", "/backups")
	if err != nil {
		t.Fatal(err)
	}
	tests := []Image{
		{Service: "unknown", Repository: approvedRegistryPrefix + "unknown", ID: "sha256:" + strings.Repeat("a", 64)},
		{Service: "gvmd", Repository: "docker.io/gvmd", ID: "sha256:" + strings.Repeat("a", 64)},
		{Service: "gvmd", Repository: approvedRegistryPrefix + "gvmd", ID: "invalid"},
		{Service: "gvmd", Repository: approvedRegistryPrefix + "gvmd", ID: "sha256:" + strings.Repeat("a", 64), Tag: "bad/tag"},
	}
	for _, image := range tests {
		if err := compose.validateImage(image); err == nil {
			t.Errorf("validateImage(%#v) error = nil", image)
		}
	}
	failing, err := NewCompose(&recordingExecutor{outputErr: errors.New("docker failed")}, "/compose.yaml", "greenbone", "/backups")
	if err != nil {
		t.Fatal(err)
	}
	if err := failing.PullStack(t.Context()); err == nil {
		t.Fatal("PullStack() error = nil")
	}
	if err := failing.ApplyStack(t.Context()); err == nil {
		t.Fatal("ApplyStack() error = nil")
	}
	if _, err := decodeImages([]byte("not json")); err == nil {
		t.Fatal("decodeImages(invalid) error = nil")
	}
}

func TestComposeSnapshotAndBackupErrorPaths(t *testing.T) {
	t.Parallel()

	unapproved := &recordingExecutor{output: []byte(`[{"Service":"gvmd","Repository":"docker.io/untrusted/gvmd","Tag":"latest"}]`)}
	compose, err := NewCompose(unapproved, "/compose.yaml", "greenbone", "/backups")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compose.Snapshot(t.Context(), []string{"gvmd"}); err == nil {
		t.Fatal("Snapshot(unapproved repository) error = nil")
	}

	invalidConfig := &recordingExecutor{output: []byte("not json")}
	compose, err = NewCompose(invalidConfig, "/compose.yaml", "greenbone", "/backups")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compose.ResolvedSnapshot(t.Context(), []string{"gvmd"}); err == nil {
		t.Fatal("ResolvedSnapshot(invalid config) error = nil")
	}

	unapproved.outputs = [][]byte{[]byte(`{"services":{"gvmd":{"image":"docker.io/untrusted/gvmd"}}}`)}
	if _, err := composeFromExecutor(t, unapproved).ResolvedSnapshot(t.Context(), []string{"gvmd"}); err == nil {
		t.Fatal("ResolvedSnapshot(unapproved repository) error = nil")
	}

	badInspect := &recordingExecutor{outputs: [][]byte{
		[]byte(`{"services":{"gvmd":{"image":"registry.community.greenbone.net/community/gvmd:stable"}}}`),
		[]byte("not json"),
	}}
	if _, err := composeFromExecutor(t, badInspect).ResolvedSnapshot(t.Context(), []string{"gvmd"}); err == nil {
		t.Fatal("ResolvedSnapshot(invalid inspection) error = nil")
	}

	directory := t.TempDir()
	backupFailure := &recordingExecutor{outputToErr: errors.New("pg_dump failed")}
	backupCompose, err := NewCompose(backupFailure, filepath.Join(directory, "compose.yaml"), "greenbone", directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backupCompose.Backup(t.Context(), "failed-operation"); err == nil {
		t.Fatal("Backup(command failure) error = nil")
	}
	if _, err := os.Stat(filepath.Join(directory, "failed-operation.dump")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("failed backup remains on disk: %v", err)
	}
	missingCompose, err := NewCompose(&recordingExecutor{}, "/compose.yaml", "greenbone", filepath.Join(directory, "missing"))
	if err != nil {
		t.Fatal(err)
	}
	if err := missingCompose.PruneBackups(3, ""); err != nil {
		t.Fatalf("PruneBackups(missing directory) error = %v", err)
	}
}

func TestComposeValidationAndRollbackFailures(t *testing.T) {
	directory := t.TempDir()
	composePath := filepath.Join(directory, "compose.yaml")
	if err := os.WriteFile(composePath, []byte("services: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	validationTests := []struct {
		name     string
		executor *recordingExecutor
	}{
		{name: "docker version", executor: &recordingExecutor{outputErr: errors.New("offline")}},
		{name: "compose config", executor: &recordingExecutor{outputErr: errors.New("invalid compose"), failAt: 2}},
		{name: "invalid JSON", executor: &recordingExecutor{outputs: [][]byte{[]byte("27.0"), []byte("not json")}}},
		{name: "missing service", executor: &recordingExecutor{outputs: [][]byte{[]byte("27.0"), []byte(`{"services":{}}`)}}},
	}
	for _, test := range validationTests {
		t.Run(test.name, func(t *testing.T) {
			compose, err := NewCompose(test.executor, composePath, "greenbone", directory)
			if err != nil {
				t.Fatal(err)
			}
			if err := compose.Validate(t.Context()); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}

	validImage := Image{
		Service: "gvmd", Repository: approvedRegistryPrefix + "gvmd", Tag: "stable",
		ID: "sha256:" + strings.Repeat("a", 64),
	}
	tagFailure := composeFromExecutor(t, &recordingExecutor{outputErr: errors.New("tag failed")})
	if err := tagFailure.Rollback(t.Context(), []Image{validImage}, ""); err == nil {
		t.Fatal("Rollback(tag failure) error = nil")
	}
	applyFailure := composeFromExecutor(t, &recordingExecutor{outputErr: errors.New("apply failed")})
	if err := applyFailure.Rollback(t.Context(), nil, ""); err == nil {
		t.Fatal("Rollback(apply failure) error = nil")
	}

	rollbackCompose, err := NewCompose(&recordingExecutor{}, composePath, "greenbone", directory)
	if err != nil {
		t.Fatal(err)
	}
	missingBackup := filepath.Join(directory, "missing.dump")
	if err := rollbackCompose.Rollback(t.Context(), nil, missingBackup); err == nil {
		t.Fatal("Rollback(missing backup) error = nil")
	}
	backupPath := filepath.Join(directory, "restore.dump")
	if err := os.WriteFile(backupPath, []byte("backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	restoreFailure, err := NewCompose(&recordingExecutor{inputErr: errors.New("restore failed")}, composePath, "greenbone", directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := restoreFailure.Rollback(t.Context(), nil, backupPath); err == nil {
		t.Fatal("Rollback(restore failure) error = nil")
	}
}

func composeFromExecutor(t *testing.T, executor DockerExecutor) *Compose {
	t.Helper()
	compose, err := NewCompose(executor, "/compose.yaml", "greenbone", "/backups")
	if err != nil {
		t.Fatal(err)
	}
	return compose
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
