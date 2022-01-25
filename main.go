package main

import (
	"embed"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"text/template"

	"golang.org/x/term"
	"gopkg.in/alessio/shellescape.v1"
)

var (
	//go:embed *.tmpl
	templatesFS embed.FS
	templates   = template.Must(template.ParseFS(templatesFS, "*.tmpl"))

	skipPasswordCheck = flag.Bool("skip_password_check", false, "Do not check entered passwords")
	outputFile        = flag.String("output_file", "/zfs-reboot-passphrase.sh", "Write output to this file (blank is stdout)")
)

func main() {
	flag.Parse()

	mustBeRoot()

	fileSystems, err := fileSystemsWithKeyStatus()
	if err != nil {
		panic(err)
	}

	templateData := map[string]string{}

	for _, fs := range fileSystems {
		if password := getPassword(fs); password != "" {
			templateData[fs] = shellescape.Quote(password)
		} else {
			fmt.Fprintln(os.Stderr, "Skipping", fs)
		}
	}

	var out = os.Stdout
	if *outputFile != "" {
		var err error
		out, err = os.OpenFile(*outputFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0700)
		if err != nil {
			panic("Can't write to " + *outputFile + ": " + err.Error())
		}
	}

	templates.Execute(out, templateData)
	if out != os.Stdout {
		fmt.Fprintln(os.Stderr, "Wrote", *outputFile)
	}
}

func getPassword(fs string) string {
	for {
		fmt.Fprintf(os.Stderr, "Password for %s (empty to skip): ", fs)
		pass, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)

		if err != nil {
			continue
		}

		if len(pass) == 0 {
			return ""
		}

		if err := checkPassword(fs, string(pass)); err != nil {
			fmt.Fprintf(os.Stderr, "Password mismatch: %v\n", err)
			continue
		}

		return string(pass)
	}
}

func mustBeRoot() {
	u, err := user.Current()
	if err != nil {
		panic("Could not check I'm root")
	}
	if u.Uid != "0" {
		panic("Must run as root")
	}
}

func fileSystemsWithKeyStatus() ([]string, error) {
	var result []string
	keyStatus, err := exec.Command("zfs", "get", "-H", "-t", "filesystem", "keystatus").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to check filesystems with keys: %w", err)
	}
	for _, line := range strings.Split(string(keyStatus), "\n") {
		spl := strings.Fields(string(line))
		if len(spl) >= 2 && spl[2] == "available" {
			result = append(result, spl[0])
		}
	}

	return result, nil
}

func checkPassword(fs, password string) error {
	if *skipPasswordCheck {
		return nil
	}
	cmd := exec.Command("zfs", "load-key", "-n", fs)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to send password to zfs load-key: %w", err)
	}
	go func() {
		defer stdin.Close()
		io.WriteString(stdin, password)
	}()
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("password verification failed: %s", strings.TrimSpace(string(output)))
	}

	return nil
}
