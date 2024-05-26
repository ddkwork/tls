// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ddkwork/golibrary/mylog"
)

// Tests that the linker is able to remove references to the Client or Server if unused.
func TestLinkerGC(t *testing.T) {
	t.Skip()
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	t.Parallel()
	goBin := os.Getenv("GOBIN")
	// goBin := testenv.GoToolPath(t)
	// testenv.MustHaveGoBuild(t)

	tests := []struct {
		name    string
		program string
		want    []string
		bad     []string
	}{
		{
			name: "empty_import",
			program: `package main
import _ "crypto/tls"
func main() {}
`,
			bad: []string{
				"tls.(*Conn)",
				"type:crypto/tls.clientHandshakeState",
				"type:crypto/tls.serverHandshakeState",
			},
		},
		{
			name: "client_and_server",
			program: `package main
import "crypto/tls"
func main() {
  tls.Dial("", "", nil)
  tls.Server(nil, nil)
}
`,
			want: []string{
				"crypto/tls.(*Conn).clientHandshake",
				"crypto/tls.(*Conn).serverHandshake",
			},
		},
		{
			name: "only_client",
			program: `package main
import "crypto/tls"
func main() { tls.Dial("", "", nil) }
`,
			want: []string{
				"crypto/tls.(*Conn).clientHandshake",
			},
			bad: []string{
				"crypto/tls.(*Conn).serverHandshake",
			},
		},
		// TODO: add only_server like func main() { tls.Server(nil, nil) }
		// That currently brings in the client via Conn.handleRenegotiation.

	}
	tmpDir := t.TempDir()
	goFile := filepath.Join(tmpDir, "x.go")
	exeFile := filepath.Join(tmpDir, "x.exe")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mylog.Check(os.WriteFile(goFile, []byte(tt.program), 0644))

			os.Remove(exeFile)
			cmd := exec.Command(goBin, "build", "-o", "x.exe", "x.go")
			cmd.Dir = tmpDir
			mylog.Check2(cmd.CombinedOutput())

			cmd = exec.Command(goBin, "tool", "nm", "x.exe")
			cmd.Dir = tmpDir
			nm := mylog.Check2(cmd.CombinedOutput())

			for _, sym := range tt.want {
				if !bytes.Contains(nm, []byte(sym)) {
					t.Errorf("expected symbol %q not found", sym)
				}
			}
			for _, sym := range tt.bad {
				if bytes.Contains(nm, []byte(sym)) {
					t.Errorf("unexpected symbol %q found", sym)
				}
			}
		})
	}
}
