package modules

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"

	"github.com/autonomouspen/scanner/internal/scanner"
)

type GitExposureScanner struct {
	httpClient *http.Client
}

func NewGitExposureScanner() *GitExposureScanner {
	return &GitExposureScanner{
		httpClient: &http.Client{},
	}
}

type Secret struct {
	Type    string
	Content string
	File    string
}

func (s *GitExposureScanner) Scan(ctx context.Context, target *Target, results chan<- *scanner.Vulnerability) {
	// Check for .git directory
	if s.checkGitExposed(target) {
		s.extractGitData(ctx, target, results)
		s.findSensitiveFiles(ctx, target, results)
		s.extractCommitHistory(ctx, target, results)
		s.findSecrets(ctx, target, results)
	}

	// Check for other version control systems
	s.checkSVN(ctx, target, results)
	s.checkMercurial(ctx, target, results)
	s.checkCVS(ctx, target, results)
}

func (s *GitExposureScanner) checkGitExposed(target *Target) bool {
	gitPaths := []string{
		".git/config",
		".git/HEAD",
		".git/index",
		".git/description",
		".git/hooks/",
		".git/info/",
		".git/objects/",
		".git/refs/",
		".git/logs/HEAD",
		".git/COMMIT_EDITMSG",
	}

	for _, path := range gitPaths {
		url := target.URL + "/" + path
		resp, err := s.httpClient.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			return true
		}
	}

	return false
}

func (s *GitExposureScanner) extractGitData(ctx context.Context, target *Target, results chan<- *scanner.Vulnerability) {
	// Download .git directory
	gitDumper := &GitDumper{
		Target: target,
		Output: "/tmp/git_" + s.randomString(10),
	}

	if err := gitDumper.Dump(); err == nil {
		// Analyze downloaded repository
		secrets := s.findSecretsInRepo(gitDumper.Output)

		for _, secret := range secrets {
			vuln := &scanner.Vulnerability{
				Name:     "Git Repository Exposure",
				Severity: "Critical",
				Description:  fmt.Sprintf("Found secret: %s in %s", secret.Type, secret.File),
				Evidence: secret.Content,
			}
			results <- vuln
		}
	}
}

func (s *GitExposureScanner) findSensitiveFiles(ctx context.Context, target *Target, results chan<- *scanner.Vulnerability) {
	// Implementation for finding sensitive files
}

func (s *GitExposureScanner) extractCommitHistory(ctx context.Context, target *Target, results chan<- *scanner.Vulnerability) {
	// Implementation for extracting commit history
}

func (s *GitExposureScanner) findSecrets(ctx context.Context, target *Target, results chan<- *scanner.Vulnerability) {
	// Implementation for finding secrets
}

func (s *GitExposureScanner) checkSVN(ctx context.Context, target *Target, results chan<- *scanner.Vulnerability) {
	// Implementation for checking SVN exposure
}

func (s *GitExposureScanner) checkMercurial(ctx context.Context, target *Target, results chan<- *scanner.Vulnerability) {
	// Implementation for checking Mercurial exposure
}

func (s *GitExposureScanner) checkCVS(ctx context.Context, target *Target, results chan<- *scanner.Vulnerability) {
	// Implementation for checking CVS exposure
}

func (s *GitExposureScanner) findSecretsInRepo(repoPath string) []Secret {
	var secrets []Secret

	// Patterns for different secret types
	patterns := map[string]*regexp.Regexp{
		"AWS Key":      regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"AWS Secret":   regexp.MustCompile(`[0-9a-zA-Z/+=]{40}`),
		"API Key":      regexp.MustCompile(`api[_-]?key[_-]?=?[\"']?([0-9a-zA-Z\-_]{20,})[\"']?`),
		"Private Key":  regexp.MustCompile(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`),
		"JWT Secret":   regexp.MustCompile(`jwt[_-]?secret[_-]?=?[\"']?([0-9a-zA-Z\-_]{20,})[\"']?`),
		"Database URL": regexp.MustCompile(`(mongodb|mysql|postgres|redis)://[^\s]+`),
		"Slack Token":  regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z-]+`),
		"GitHub Token": regexp.MustCompile(`gh[pousr]_[0-9a-zA-Z]{36}`),
	}

	// Search through all files
	filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		content, _ := ioutil.ReadFile(path)

		for secretType, pattern := range patterns {
			if matches := pattern.FindAll(content, -1); len(matches) > 0 {
				for _, match := range matches {
					secrets = append(secrets, Secret{
						Type:    secretType,
						Content: string(match),
						File:    path,
					})
				}
			}
		}

		return nil
	})

	return secrets
}

type GitDumper struct {
	Target *Target
	Output string
}

func (d *GitDumper) Dump() error {
	// Implementation for dumping a git repository
	return nil
}

func (s *GitExposureScanner) randomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
