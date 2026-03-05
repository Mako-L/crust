package pwsh

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"sync"
	"unicode/utf16"
)

//go:embed ps_bootstrap_header.ps1
var psHeader string

//go:embed ps_bootstrap_vars.ps1
var psVars string

//go:embed ps_bootstrap_cmds.ps1
var psCmds string

//go:embed ps_bootstrap_dotnet.ps1
var psDotNet string

//go:embed ps_bootstrap_footer.ps1
var psFooter string

var psBootstrapScript = psHeader + psVars + psCmds + psDotNet + psFooter

// pwshWorkerRequest is the IPC request sent from Go → pwsh worker.
type pwshWorkerRequest struct {
	Command string `json:"command"`
}

// ParsedCommand represents a single command extracted from the PowerShell AST.
// Field names and JSON tags match the PSCustomObject emitted by the bootstrap script.
type ParsedCommand struct {
	Name         string   `json:"name"`
	Args         []string `json:"args"`
	RedirPaths   []string `json:"redir_paths"`
	RedirInPaths []string `json:"redir_in_paths"`
	HasSubst     bool     `json:"has_subst"`
}

// Response is the IPC response received from the pwsh worker subprocess.
type Response struct {
	Commands    []ParsedCommand `json:"commands"`
	ParseErrors []string        `json:"parseErrors"`
}

// Worker manages a persistent pwsh subprocess for accurate PowerShell
// command analysis. It mirrors the shellWorker pattern: JSON over stdin/stdout,
// auto-restart on crash, mutex-serialized access.
type Worker struct {
	mu       sync.Mutex
	proc     *exec.Cmd
	stdin    io.WriteCloser
	scanner  *bufio.Scanner
	encoder  *json.Encoder // reused across Parse() calls to avoid per-call allocation
	pwshPath string        // path to pwsh.exe or powershell.exe
	encoded  string        // base64 UTF-16LE encoded bootstrap script
}

// FindPwsh returns the path to pwsh.exe or powershell.exe, preferring the
// newer pwsh (PowerShell 7+) over legacy powershell (Windows PowerShell 5.1).
// On supported Windows 10/11 systems, powershell.exe is always present so
// this should always succeed.
func FindPwsh() (string, bool) {
	for _, name := range []string{"pwsh.exe", "powershell.exe"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, true
		}
	}
	return "", false
}

// NewWorker creates and starts a pwsh worker subprocess.
func NewWorker(pwshPath string) (*Worker, error) {
	w := &Worker{
		pwshPath: pwshPath,
		encoded:  encodePSCommand(psBootstrapScript),
	}
	if err := w.start(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Worker) start() error {
	proc := exec.CommandContext(context.Background(), w.pwshPath, //nolint:gosec // pwshPath comes from exec.LookPath, not user input
		"-NoProfile", "-NonInteractive", "-EncodedCommand", w.encoded)
	stdin, err := proc.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := proc.StdoutPipe()
	if err != nil {
		stdin.Close()
		return err
	}
	proc.Stderr = io.Discard

	if err := proc.Start(); err != nil {
		stdin.Close()
		return err
	}

	w.proc = proc
	w.stdin = stdin
	w.encoder = json.NewEncoder(stdin)
	w.scanner = bufio.NewScanner(stdout)
	w.scanner.Buffer(make([]byte, 1<<20), 1<<20)
	return nil
}

// Parse sends a command to the pwsh worker and returns the parsed result.
// Returns an error if the worker died or the response was malformed; the
// worker is automatically restarted on the next call.
func (w *Worker) Parse(cmd string) (Response, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.proc == nil {
		if err := w.start(); err != nil {
			return Response{}, err
		}
	}

	if err := w.encoder.Encode(pwshWorkerRequest{Command: cmd}); err != nil {
		w.kill()
		return Response{}, err
	}

	if !w.scanner.Scan() {
		w.kill()
		return Response{}, errors.New("pwsh worker: unexpected EOF")
	}

	var resp Response
	if err := json.Unmarshal(w.scanner.Bytes(), &resp); err != nil {
		w.kill()
		return Response{}, err
	}

	return resp, nil
}

func (w *Worker) kill() {
	if w.stdin != nil {
		w.stdin.Close() // close write end before Kill to avoid fd leak
	}
	if w.proc != nil && w.proc.Process != nil {
		w.proc.Process.Kill()
		proc := w.proc
		go proc.Wait() // async reap; error irrelevant after Kill()
	}
	w.proc = nil
	w.stdin = nil
	w.encoder = nil
	w.scanner = nil
}

// Stop shuts down the pwsh worker subprocess.
func (w *Worker) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.kill() // kill() closes stdin before sending SIGKILL
}

// encodePSCommand encodes a PowerShell script as base64 UTF-16LE for use
// with pwsh -EncodedCommand. PowerShell expects little-endian UTF-16.
func encodePSCommand(s string) string {
	runes := utf16.Encode([]rune(s))
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return base64.StdEncoding.EncodeToString(buf)
}
