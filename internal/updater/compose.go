package updater

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

func dockerCommand(ctx context.Context, args ...string) *exec.Cmd {
	// #nosec G204,G702 -- the executable is fixed; callers expose only allowlisted
	// Compose operations and validated deployment configuration, never a shell.
	return exec.CommandContext(ctx, "docker", args...)
}

const (
	approvedRegistryPrefix = "registry.community.greenbone.net/community/"
	maxCommandOutput       = 64 << 10
)

var feedServices = []string{
	"notus-data",
	"vulnerability-tests",
	"scap-data",
	"dfn-cert-data",
	"cert-bund-data",
	"report-formats",
	"data-objects",
}

var stackServices = []string{
	"vulnerability-tests",
	"notus-data",
	"scap-data",
	"cert-bund-data",
	"dfn-cert-data",
	"data-objects",
	"report-formats",
	"gpg-data",
	"redis-server",
	"pg-gvm-migrator",
	"pg-gvm",
	"gvmd",
	"gsa",
	"gsad",
	"gvm-config",
	"nginx",
	"configure-openvas",
	"openvas",
	"openvasd",
	"ospd-openvas",
	"gvm-tools",
}

type DockerExecutor interface {
	Output(ctx context.Context, args ...string) ([]byte, error)
	OutputTo(ctx context.Context, output io.Writer, args ...string) error
	InputFrom(ctx context.Context, input io.Reader, args ...string) error
}

type OSCommandExecutor struct{}

func (OSCommandExecutor) Output(
	ctx context.Context,
	args ...string,
) ([]byte, error) {
	command := dockerCommand(ctx, args...)
	var stdout, stderr limitedBuffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, commandFailure(err, stderr.String())
	}
	return stdout.Bytes(), nil
}

func (OSCommandExecutor) OutputTo(
	ctx context.Context,
	output io.Writer,
	args ...string,
) error {
	command := dockerCommand(ctx, args...)
	var stderr limitedBuffer
	command.Stdout = output
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return commandFailure(err, stderr.String())
	}
	return nil
}

func (OSCommandExecutor) InputFrom(
	ctx context.Context,
	input io.Reader,
	args ...string,
) error {
	command := dockerCommand(ctx, args...)
	var stdout, stderr limitedBuffer
	command.Stdin = input
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return commandFailure(err, stderr.String())
	}
	return nil
}

type limitedBuffer struct {
	buffer bytes.Buffer
	full   bool
}

func (b *limitedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := maxCommandOutput - b.buffer.Len()
	if remaining <= 0 {
		b.full = true
		return original, nil
	}
	if len(value) > remaining {
		value = value[:remaining]
		b.full = true
	}
	_, _ = b.buffer.Write(value)
	return original, nil
}

func (b *limitedBuffer) Bytes() []byte {
	return b.buffer.Bytes()
}

func (b *limitedBuffer) String() string {
	value := strings.TrimSpace(b.buffer.String())
	if b.full {
		value += " [output truncated]"
	}
	return value
}

func commandFailure(err error, stderr string) error {
	if stderr == "" {
		return fmt.Errorf("running docker: %w", err)
	}
	return fmt.Errorf("running docker: %w: %s", err, stderr)
}

type Compose struct {
	executor   DockerExecutor
	file       string
	project    string
	backupDir  string
	feedGroup  []string
	stackGroup []string
}

func NewCompose(executor DockerExecutor, file, project, backupDir string) (*Compose, error) {
	if executor == nil {
		return nil, errors.New("updater: command executor is required")
	}
	cleanFile, ok := absolutePath(file)
	if !ok {
		return nil, errors.New("updater: Compose file path must be absolute")
	}
	cleanBackupDir, ok := absolutePath(backupDir)
	if !ok {
		return nil, errors.New("updater: backup directory must be absolute")
	}
	if !validProjectName(project) {
		return nil, errors.New("updater: Compose project name is invalid")
	}
	return &Compose{
		executor:   executor,
		file:       cleanFile,
		project:    project,
		backupDir:  cleanBackupDir,
		feedGroup:  append([]string(nil), feedServices...),
		stackGroup: append([]string(nil), stackServices...),
	}, nil
}

func absolutePath(value string) (string, bool) {
	if strings.HasPrefix(value, "/") {
		return path.Clean(value), true
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value), true
	}
	return "", false
}

func validProjectName(value string) bool {
	if value == "" || len(value) > 63 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			continue
		}
		if index > 0 && (character == '-' || character == '_') {
			continue
		}
		return false
	}
	return true
}

func (c *Compose) Validate(ctx context.Context) error {
	composeRoot, err := os.OpenRoot(filepath.Dir(c.file))
	if err != nil {
		return fmt.Errorf("opening Compose directory: %w", err)
	}
	defer func() { _ = composeRoot.Close() }()
	if _, err := composeRoot.Stat(filepath.Base(c.file)); err != nil {
		return fmt.Errorf("checking Compose file: %w", err)
	}
	if _, err := c.executor.Output(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		return fmt.Errorf("checking Docker: %w", err)
	}
	contents, err := c.executor.Output(ctx, c.args("config", "--format", "json")...)
	if err != nil {
		return fmt.Errorf("validating Compose project: %w", err)
	}
	var document struct {
		Services map[string]struct {
			Image string `json:"image"`
		} `json:"services"`
	}
	if err := json.Unmarshal(contents, &document); err != nil {
		return fmt.Errorf("decoding Compose configuration: %w", err)
	}
	for _, service := range c.stackGroup {
		configured, ok := document.Services[service]
		if !ok {
			return fmt.Errorf("updater: required service %q is absent from Compose project", service)
		}
		if !strings.HasPrefix(configured.Image, approvedRegistryPrefix) {
			return fmt.Errorf("updater: service %q uses an unapproved image", service)
		}
	}
	return nil
}

func (c *Compose) Snapshot(ctx context.Context, services []string) ([]Image, error) {
	if err := c.validateServices(services); err != nil {
		return nil, err
	}
	arguments := c.args("images", "--format", "json")
	arguments = append(arguments, services...)
	contents, err := c.executor.Output(ctx, arguments...)
	if err != nil {
		return nil, fmt.Errorf("reading Compose images: %w", err)
	}
	images, err := decodeImages(contents)
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]bool, len(services))
	for _, service := range services {
		allowed[service] = true
	}
	result := make([]Image, 0, len(images))
	for _, image := range images {
		if !allowed[image.Service] {
			continue
		}
		if !strings.HasPrefix(image.Repository, approvedRegistryPrefix) {
			return nil, fmt.Errorf("updater: service %q resolved an unapproved repository", image.Service)
		}
		result = append(result, image)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].Service < result[right].Service
	})
	return result, nil
}

func (c *Compose) ResolvedSnapshot(ctx context.Context, services []string) ([]Image, error) {
	if err := c.validateServices(services); err != nil {
		return nil, err
	}
	contents, err := c.executor.Output(ctx, c.args("config", "--format", "json")...)
	if err != nil {
		return nil, fmt.Errorf("reading configured images: %w", err)
	}
	var document struct {
		Services map[string]struct {
			Image string `json:"image"`
		} `json:"services"`
	}
	if err := json.Unmarshal(contents, &document); err != nil {
		return nil, fmt.Errorf("decoding configured images: %w", err)
	}
	result := make([]Image, 0, len(services))
	for _, service := range services {
		reference := document.Services[service].Image
		if !strings.HasPrefix(reference, approvedRegistryPrefix) {
			return nil, fmt.Errorf("updater: service %q resolved an unapproved repository", service)
		}
		inspect, inspectErr := c.executor.Output(
			ctx,
			"image",
			"inspect",
			"--format",
			"{{json .}}",
			reference,
		)
		if inspectErr != nil {
			return nil, fmt.Errorf("inspecting image for %s: %w", service, inspectErr)
		}
		var value struct {
			ID string `json:"Id"`
		}
		if err := json.Unmarshal(bytes.TrimSpace(inspect), &value); err != nil {
			return nil, fmt.Errorf("decoding image inspection for %s: %w", service, err)
		}
		repository, tag := splitImageReference(reference)
		result = append(result, Image{Service: service, Repository: repository, Tag: tag, ID: value.ID})
	}
	return sortedImages(result), nil
}

func splitImageReference(reference string) (string, string) {
	lastSlash := strings.LastIndexByte(reference, '/')
	lastColon := strings.LastIndexByte(reference, ':')
	if lastColon > lastSlash {
		return reference[:lastColon], reference[lastColon+1:]
	}
	return reference, "latest"
}

func decodeImages(contents []byte) ([]Image, error) {
	type wireImage struct {
		ID         string `json:"ID"`
		Repository string `json:"Repository"`
		Service    string `json:"Service"`
		Tag        string `json:"Tag"`
	}
	var list []wireImage
	if err := json.Unmarshal(contents, &list); err != nil {
		scanner := bufio.NewScanner(bytes.NewReader(contents))
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == "" {
				continue
			}
			var value wireImage
			if lineErr := json.Unmarshal(scanner.Bytes(), &value); lineErr != nil {
				return nil, fmt.Errorf("decoding Compose image list: %w", err)
			}
			list = append(list, value)
		}
		if scanErr := scanner.Err(); scanErr != nil {
			return nil, fmt.Errorf("reading Compose image list: %w", scanErr)
		}
	}
	result := make([]Image, 0, len(list))
	for _, value := range list {
		result = append(result, Image{
			Service: value.Service, Repository: value.Repository, Tag: value.Tag, ID: value.ID,
		})
	}
	return result, nil
}

func (c *Compose) PullFeed(ctx context.Context) error {
	return c.pull(ctx, c.feedGroup)
}

func (c *Compose) PullStack(ctx context.Context) error {
	return c.pull(ctx, c.stackGroup)
}

func (c *Compose) pull(ctx context.Context, services []string) error {
	arguments := c.args("pull", "--quiet")
	arguments = append(arguments, services...)
	if _, err := c.executor.Output(ctx, arguments...); err != nil {
		return fmt.Errorf("pulling approved images: %w", err)
	}
	return nil
}

func (c *Compose) ApplyFeed(ctx context.Context) error {
	return c.up(ctx, c.feedGroup)
}

func (c *Compose) ApplyStack(ctx context.Context) error {
	return c.up(ctx, c.stackGroup)
}

func (c *Compose) up(ctx context.Context, services []string) error {
	arguments := c.args("up", "-d", "--no-build")
	arguments = append(arguments, services...)
	if _, err := c.executor.Output(ctx, arguments...); err != nil {
		return fmt.Errorf("applying approved services: %w", err)
	}
	return nil
}

func (c *Compose) Backup(ctx context.Context, operationID string) (string, error) {
	if !validIdentifier(operationID) {
		return "", errors.New("updater: operation identifier is invalid")
	}
	root, err := os.OpenRoot(c.backupDir)
	if err != nil {
		return "", fmt.Errorf("opening backup directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	name := operationID + ".dump"
	path := filepath.Join(c.backupDir, name)
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("creating database backup: %w", err)
	}
	arguments := c.args("exec", "-T", "pg-gvm", "pg_dump", "-U", "gvmd", "-d", "gvmd", "-Fc")
	runErr := c.executor.OutputTo(ctx, file, arguments...)
	closeErr := file.Close()
	if runErr != nil || closeErr != nil {
		_ = root.Remove(name)
		return "", errors.Join(runErr, closeErr)
	}
	return path, nil
}

func (c *Compose) Rollback(
	ctx context.Context,
	images []Image,
	backupPath string,
) error {
	for _, image := range images {
		if err := c.validateImage(image); err != nil {
			return err
		}
		target := image.Repository
		if image.Tag != "" && image.Tag != "<none>" {
			target += ":" + image.Tag
		}
		if _, err := c.executor.Output(ctx, "image", "tag", image.ID, target); err != nil {
			return fmt.Errorf("restoring image for %s: %w", image.Service, err)
		}
	}
	if backupPath != "" {
		clean := filepath.Clean(backupPath)
		if filepath.Dir(clean) != c.backupDir {
			return errors.New("updater: backup path is outside the backup directory")
		}
		root, err := os.OpenRoot(c.backupDir)
		if err != nil {
			return fmt.Errorf("opening backup directory: %w", err)
		}
		defer func() { _ = root.Close() }()
		if _, err := c.executor.Output(ctx, c.args("stop", "gvmd", "gsad")...); err != nil {
			return fmt.Errorf("stopping database clients for rollback: %w", err)
		}
		file, err := root.Open(filepath.Base(clean))
		if err != nil {
			return fmt.Errorf("opening rollback backup: %w", err)
		}
		arguments := c.args(
			"exec", "-T", "pg-gvm", "pg_restore", "--clean", "--if-exists",
			"--no-owner", "-U", "gvmd", "-d", "gvmd",
		)
		restoreErr := c.executor.InputFrom(ctx, file, arguments...)
		closeErr := file.Close()
		if restoreErr != nil || closeErr != nil {
			return errors.Join(restoreErr, closeErr)
		}
	}
	return c.ApplyStack(ctx)
}

func (c *Compose) PruneBackups(retain int, protected string) error {
	root, err := os.OpenRoot(c.backupDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("opening backup directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return fmt.Errorf("reading backup directory: %w", err)
	}
	type backupFile struct {
		name    string
		modTime int64
	}
	files := make([]backupFile, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".dump") {
			continue
		}
		if filepath.Join(c.backupDir, entry.Name()) == protected {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return fmt.Errorf("reading backup metadata: %w", infoErr)
		}
		files = append(files, backupFile{name: entry.Name(), modTime: info.ModTime().UnixNano()})
	}
	sort.Slice(files, func(left, right int) bool { return files[left].modTime > files[right].modTime })
	if retain >= len(files) {
		return nil
	}
	for _, file := range files[retain:] {
		if err := root.Remove(file.name); err != nil {
			return fmt.Errorf("removing expired backup: %w", err)
		}
	}
	return nil
}

func (c *Compose) FeedServices() []string {
	return append([]string(nil), c.feedGroup...)
}

func (c *Compose) StackServices() []string {
	return append([]string(nil), c.stackGroup...)
}

func (c *Compose) args(values ...string) []string {
	result := []string{"compose", "--project-name", c.project, "--file", c.file}
	return append(result, values...)
}

func (c *Compose) validateServices(services []string) error {
	allowed := make(map[string]bool, len(c.stackGroup))
	for _, service := range c.stackGroup {
		allowed[service] = true
	}
	for _, service := range services {
		if !allowed[service] {
			return fmt.Errorf("updater: service %q is not allowlisted", service)
		}
	}
	return nil
}

func (c *Compose) validateImage(image Image) error {
	if err := c.validateServices([]string{image.Service}); err != nil {
		return err
	}
	if !strings.HasPrefix(image.Repository, approvedRegistryPrefix) {
		return fmt.Errorf("updater: image repository for %q is not allowlisted", image.Service)
	}
	if !strings.HasPrefix(image.ID, "sha256:") || len(image.ID) != len("sha256:")+64 {
		return fmt.Errorf("updater: image digest for %q is invalid", image.Service)
	}
	if strings.ContainsAny(image.Tag, "/\\:@ ") {
		return fmt.Errorf("updater: image tag for %q is invalid", image.Service)
	}
	return nil
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 80 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
			continue
		}
		return false
	}
	return true
}
