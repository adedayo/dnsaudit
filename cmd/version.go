package cmd

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// Build metadata. These are populated at release time via -ldflags by
// GoReleaser (see .goreleaser.yml). When dnsaudit is built with plain
// `go build` or installed with `go install`, they fall back to the values
// embedded by the Go toolchain in the module's build info.
var (
	version = ""
	commit  = ""
	date    = ""
)

// SetBuildInfo allows main() to inject build metadata.
func SetBuildInfo(v, c, d string) {
	if v != "" {
		version = v
	}
	if c != "" {
		commit = c
	}
	if d != "" {
		date = d
	}
}

// buildInfo resolves the version, commit and build date, preferring values
// injected at link time and falling back to the embedded module build info.
func buildInfo() (v, c, d string) {
	v, c, d = version, commit, date

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return orUnknown(v), orUnknown(c), orUnknown(d)
	}

	if v == "" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		v = info.Main.Version
	}

	// Only derive VCS details when they were not injected at link time.
	fromVCS := c == ""
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			if fromVCS {
				c = setting.Value
			}
		case "vcs.time":
			if d == "" {
				d = setting.Value
			}
		case "vcs.modified":
			if fromVCS && setting.Value == "true" {
				c += "-dirty"
			}
		}
	}
	return orUnknown(v), orUnknown(c), orUnknown(d)
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// versionString renders the one-line version summary used by --version.
func versionString() string {
	v, c, d := buildInfo()
	return fmt.Sprintf("dnsaudit %s (commit %s, built %s, %s, %s/%s)",
		v, c, d, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// versionCmd prints detailed build information.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the dnsaudit version and build information.",
	Long: `Print the version, source commit, build date, Go toolchain and target
platform of this dnsaudit binary. Useful when reporting issues.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		v, c, d := buildInfo()
		fmt.Printf("Version   : %s\n", v)
		fmt.Printf("Commit    : %s\n", c)
		fmt.Printf("Built     : %s\n", d)
		fmt.Printf("Go        : %s\n", runtime.Version())
		fmt.Printf("Platform  : %s/%s\n", runtime.GOOS, runtime.GOARCH)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
