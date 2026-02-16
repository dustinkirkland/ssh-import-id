package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
)

// fetchKeys fetches SSH keys from the specified protocol handler
func fetchKeys(proto, username, userAgent string) ([]string, error) {
	switch proto {
	case "lp":
		return fetchKeysLaunchpad(username, userAgent)
	case "gh":
		return fetchKeysGitHub(username, userAgent)
	case "gl":
		return fetchKeysGitLab(username, userAgent)
	default:
		return nil, fmt.Errorf("ssh-import-id protocol handler %s: not found or cannot execute", proto)
	}
}

// buildUserAgent constructs the User-Agent string
func buildUserAgent(extra string) string {
	parts := []string{
		fmt.Sprintf("ssh-import-id/%s", Version),
		fmt.Sprintf("Go/%s", runtime.Version()),
		fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
	if extra != "" {
		parts = append(parts, extra)
	}
	return strings.Join(parts, " ")
}

// fetchKeysLaunchpad fetches keys from Launchpad
func fetchKeysLaunchpad(username, userAgent string) ([]string, error) {
	// Check for custom URL configuration
	urlTemplate := os.Getenv("URL")
	if urlTemplate == "" {
		// Check config file
		configFile := "/etc/ssh/ssh_import_id"
		if data, err := os.ReadFile(configFile); err == nil {
			var config map[string]string
			if err := json.Unmarshal(data, &config); err == nil {
				if u, ok := config["URL"]; ok {
					urlTemplate = u
				}
			}
		}
	}

	// Build URL
	var fetchURL string
	if urlTemplate != "" {
		// Support both old %s format and new {} format
		if strings.Contains(urlTemplate, "{}") {
			fetchURL = strings.Replace(urlTemplate, "{}", url.QueryEscape(username), 1)
		} else if strings.Contains(urlTemplate, "%s") {
			fetchURL = strings.Replace(urlTemplate, "%s", url.QueryEscape(username), 1)
		} else {
			return nil, fmt.Errorf("invalid URL template")
		}
	} else {
		// Default to Launchpad
		fetchURL = fmt.Sprintf("https://launchpad.net/~%s/+sshkeys", url.QueryEscape(username))
	}

	// Make request
	client := &http.Client{Timeout: DefaultTimeout}
	req, err := http.NewRequest("GET", fetchURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", buildUserAgent(userAgent))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Launchpad keys: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("Launchpad user not found. status_code=%d user=%s", resp.StatusCode, username)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("requesting Launchpad keys failed. status_code=%d user=%s", resp.StatusCode, username)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return parseKeys(string(body)), nil
}

// fetchKeysGitHub fetches keys from GitHub
func fetchKeysGitHub(username, userAgent string) ([]string, error) {
	fetchURL := fmt.Sprintf("https://api.github.com/users/%s/keys", url.QueryEscape(username))

	client := &http.Client{Timeout: DefaultTimeout}
	req, err := http.NewRequest("GET", fetchURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", buildUserAgent(userAgent))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch GitHub keys: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("username \"%s\" not found at GitHub API. status_code=%d user=%s", username, resp.StatusCode, username)
	}

	// Check for rate limiting
	if rateRemaining := resp.Header.Get("X-RateLimit-Remaining"); rateRemaining == "0" {
		return nil, fmt.Errorf("GitHub REST API rate-limited this IP address. See https://developer.github.com/v3/#rate-limiting . status_code=%d user=%s", resp.StatusCode, username)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("requesting GitHub keys failed. status_code=%d user=%s", resp.StatusCode, username)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse GitHub JSON response
	var keyObjects []struct {
		ID  int    `json:"id"`
		Key string `json:"key"`
	}

	if err := json.Unmarshal(body, &keyObjects); err != nil {
		return nil, fmt.Errorf("failed to parse GitHub response: %v", err)
	}

	var keys []string
	for _, obj := range keyObjects {
		key := fmt.Sprintf("%s %s@github/%d", obj.Key, username, obj.ID)
		keys = append(keys, key)
	}

	return keys, nil
}

// fetchKeysGitLab fetches keys from GitLab
func fetchKeysGitLab(username, userAgent string) ([]string, error) {
	// Check for custom GitLab URL
	gitlabURL := os.Getenv("GITLAB_URL")
	if gitlabURL == "" {
		gitlabURL = "https://gitlab.com"
	}
	gitlabURL = strings.TrimRight(gitlabURL, "/")

	fetchURL := fmt.Sprintf("%s/%s.keys", gitlabURL, url.QueryEscape(username))

	client := &http.Client{Timeout: DefaultTimeout}
	req, err := http.NewRequest("GET", fetchURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", buildUserAgent(userAgent))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch GitLab keys: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("username \"%s\" not found at GitLab. status_code=%d user=%s url=%s", username, resp.StatusCode, username, fetchURL)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("requesting GitLab keys failed. status_code=%d user=%s url=%s", resp.StatusCode, username, fetchURL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// GitLab returns keys in authorized_keys format
	lines := strings.Split(string(body), "\n")
	var keys []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			// Add GitLab identifier
			key := fmt.Sprintf("%s %s@gitlab", line, username)
			keys = append(keys, key)
		}
	}

	return keys, nil
}

// parseKeys parses SSH keys from text (used for Launchpad)
func parseKeys(text string) []string {
	var keys []string
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			keys = append(keys, line)
		}
	}
	return keys
}
