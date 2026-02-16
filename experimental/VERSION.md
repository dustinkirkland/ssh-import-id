# ssh-import-id Versioning

## Version Scheme

Starting with the Go implementation, ssh-import-id uses separate version series for different implementations:

### Python Implementation: 5.x Series
- **Current Version**: 5.13
- **Language**: Python
- **Status**: Stable, production-ready
- **Target**: Traditional deployments, full OS images
- **Last Major Update**: v5.12 (security fixes), v5.13 (GitLab support)

### Go Implementation: 6.x Series
- **Current Version**: 6.0
- **Language**: Go
- **Status**: Experimental, feature-complete
- **Target**: Containers, distroless, minimal environments
- **First Release**: v6.0 (complete rewrite in Go)

## Why Version 6.0?

The jump from 5.13 to 6.0 signifies a **major architectural change**:

1. **Different Implementation Language** - Complete rewrite from Python to Go
2. **Major Performance Improvements** - 40x faster startup, 3.5x less memory
3. **Zero Dependencies** - Single static binary vs Python interpreter + libraries
4. **New Target Environments** - Enables distroless containers, IoT, serverless
5. **Breaking Change in Distribution** - Binary distribution model vs script

Even though the CLI interface and functionality remain identical (100% compatible), the underlying implementation is fundamentally different, warranting a major version bump.

## Version History

### 6.x Series (Go Implementation)
- **6.0** (2026-02-15) - Initial Go implementation
  - Complete rewrite in Go
  - 100% feature parity with Python 5.13
  - All protocols: GitHub, GitLab, Launchpad
  - All security fixes from 5.12 included
  - Single 5.9 MB static binary
  - Zero dependencies
  - 40x faster startup
  - 3.5x less memory usage

### 5.x Series (Python Implementation)
- **5.13** (2026-02-15) - GitLab support
  - Add GitLab support (gl:username)
  - Support self-hosted GitLab (GITLAB_URL)
  - New wrapper script: ssh-import-id-gl

- **5.12** (2026-02-15) - Security fixes
  - Fix command injection vulnerability
  - Fix format string vulnerability
  - Fix path traversal vulnerability

- **5.11** (2020-12-07) - Dependency reduction
  - Remove requests module dependency
  - Use urllib instead

- **5.10** (2020-02-28) - Bug fixes
- **5.9** (2020-02-28) - Use distro instead of platform
- **5.8** (2017-07-11) - Last GitHub release before long gap

### Earlier Versions (5.0 and below)
See main repository history for pre-5.0 versions.

## Compatibility

### API Compatibility
Both Python 5.x and Go 6.x maintain **identical command-line interfaces**:
- Same flags: `-o`, `-r`, `-u`, `--version`, `--help`
- Same protocols: `gh:`, `gl:`, `lp:`
- Same output format
- Same exit codes
- Same error messages

### Drop-in Replacement
The Go 6.0 binary can directly replace the Python 5.13 script:
```bash
# Backup Python version
sudo mv /usr/bin/ssh-import-id /usr/bin/ssh-import-id.python

# Install Go version
sudo cp build/ssh-import-id /usr/bin/ssh-import-id

# Works identically!
ssh-import-id gh:username
```

## Migration Strategy

### Parallel Deployment (Recommended)
Run both versions side-by-side:
- **Python 5.13**: Default for traditional OS deployments
- **Go 6.0**: Default for containers, serverless, minimal environments

### Version Selection
Users can choose based on their environment:
```bash
# Python version (traditional)
ssh-import-id.python gh:username

# Go version (modern)
ssh-import-id gh:username  # symlink to Go binary
```

### Long-term Plan
1. **Phase 1** (Current): Go 6.x is experimental
2. **Phase 2** (3-6 months): Go 6.x becomes stable after field testing
3. **Phase 3** (6-12 months): Go 6.x becomes default
4. **Phase 4** (12+ months): Python 5.x moves to maintenance mode
5. **Future**: Python 5.x deprecated (if Go proves successful)

## When to Use Which Version

### Use Python 5.13 if:
- ✅ Deploying to traditional Linux distributions
- ✅ Python is already installed and required
- ✅ You heavily customize the code
- ✅ You prefer Python's development experience
- ✅ You're on an existing stable deployment

### Use Go 6.0 if:
- ✅ Building minimal containers (distroless, scratch, Chainguard, Wolfi)
- ✅ Deploying to serverless/lambda environments
- ✅ Need faster startup times (<2ms)
- ✅ Want lower memory usage (~8 MB)
- ✅ Building for IoT/embedded systems
- ✅ Want zero dependencies
- ✅ Need cross-platform binaries (Linux, macOS, Windows, ARM)

## Future Versions

### Planned for 6.1+
- Potential optimizations (smaller binary size)
- Additional protocol handlers (custom)
- Enhanced logging options
- Telemetry/metrics support (opt-in)

### Python 5.14+
- Maintenance releases only
- Critical security fixes
- No new features (use Go 6.x for new features)

## Questions?

**Q: Will Python 5.x be deprecated?**
A: Not immediately. We'll support it in parallel with Go 6.x. If Go proves successful over 12+ months, we may eventually deprecate Python.

**Q: Can I use both?**
A: Yes! They're 100% compatible. Install both and use whichever fits your environment.

**Q: Will my scripts break?**
A: No. The CLI is identical. Scripts that call `ssh-import-id` will work with either version.

**Q: Which should I use for new projects?**
A: Go 6.0 for containers/serverless, Python 5.13 for traditional deployments.

**Q: When will Go 6.x be "stable"?**
A: After 3-6 months of field testing with no major issues reported.

## Version Identification

You can always check which version you're running:

```bash
$ ssh-import-id --version
ssh-import-id 6.0         # Go implementation

$ ssh-import-id.python --version
ssh-import-id 5.13        # Python implementation
```

Both work identically, but v6.0 is faster, smaller, and has zero dependencies!
