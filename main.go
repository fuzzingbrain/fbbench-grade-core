// Command grade-core is the FuzzingBrain grading executor: a single-shot,
// MCP-free judge. Given an assembled oracle bundle (expected.yaml + the
// vuln/asan, vuln/cov and fixed/asan harness binaries + bench.yaml) and one
// candidate input, it runs the capability ladder (reach / crash / differential
// / class / site) and prints the verdict as JSON on stdout.
//
//	grade-core -oracle-dir /path/to/<alias> -input /path/to/candidate.bin [-rounds N]
//
// It is deliberately NOT a server and NOT an MCP tool host — the FastAPI
// backend materializes the oracle bundle (from psql + the blob store) and
// invokes this binary per grade. The judging logic (grade.go / reach.go) is
// carried over verbatim from the proven oracle so verdicts stay byte-identical;
// everything MCP/exec/file-tool related was dropped.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// setDefaultEnv sets key=val only if it is not already present, so an operator
// can always override the pinned production default from the environment.
func setDefaultEnv(key, val string) {
	if os.Getenv(key) == "" {
		os.Setenv(key, val)
	}
}

// firstExisting returns the first path in cands that exists on disk, else the
// result of fallback() (which may be ""). Used to pin toolchain locations.
func firstExisting(cands []string, fallback func() string) string {
	for _, c := range cands {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return fallback()
}

// ensurePathHas prepends dir to PATH if it is not already a member.
func ensurePathHas(dir string) {
	path := os.Getenv("PATH")
	for _, p := range filepath.SplitList(path) {
		if p == dir {
			return
		}
	}
	if path == "" {
		os.Setenv("PATH", dir)
	} else {
		os.Setenv("PATH", dir+string(os.PathListSeparator)+path)
	}
}

// server carries only the three paths the grading path reads. (The original
// mcp-server struct also held MCP/exec/netns state; none of it survives here.)
type server struct {
	bugDir    string // holds bench.yaml (harness invocation, timeout, capability_set)
	workspace string // scratch: candidate copy + per-round grader-run dirs
	oracleDir string // answer key: grader/expected.yaml + binaries/{vuln/asan,vuln/cov,fixed/asan}
}

func main() {
	oracleDir := flag.String("oracle-dir", "", "assembled oracle bundle for one challenge (required)")
	input := flag.String("input", "", "candidate input file to grade (required)")
	rounds := flag.Int("rounds", 0, "grading rounds (0 = use grader default: best-of-N single round)")
	flag.Parse()

	if *oracleDir == "" || *input == "" {
		fmt.Fprintln(os.Stderr, "grade-core: -oracle-dir and -input are required")
		flag.Usage()
		os.Exit(2)
	}
	if st, err := os.Stat(*oracleDir); err != nil || !st.IsDir() {
		fmt.Fprintf(os.Stderr, "grade-core: oracle dir not found: %s\n", *oracleDir)
		os.Exit(2)
	}

	// The oracle is trusted infra: force the full verdict (capabilities /
	// bestof / target_bug_found / evidence). The FastAPI layer decides what to
	// expose per API — grade-core always emits everything.
	os.Setenv("BENCH_GRADE_REVEAL", "1")

	// Production grading policy, encoded as defaults (each overridable by an
	// already-set env var). These are NOT cosmetic: without a symbolizer, ASAN
	// backtraces carry no file:line, so the reach/site rungs silently fail even
	// though crash/class/differential still fire — a partial, WRONG verdict.
	// Pinning them here means grade-core reproduces the deployed oracle no matter
	// how it is launched, instead of depending on the caller's environment.
	setDefaultEnv("BENCH_GRADE_ROUNDS", "3")
	setDefaultEnv("BENCH_FIXED_RUN_ATTEMPTS", "5")
	// Ensure the LLVM toolchain dir is on PATH (a non-interactive shell may drop
	// /usr/local/bin), then resolve the symbolizer by known location OR PATH.
	ensurePathHas("/usr/local/bin")
	if os.Getenv("ASAN_SYMBOLIZER_PATH") == "" {
		os.Setenv("ASAN_SYMBOLIZER_PATH", firstExisting(
			[]string{"/usr/local/bin/llvm-symbolizer", "/usr/bin/llvm-symbolizer"},
			func() string { p, _ := exec.LookPath("llvm-symbolizer"); return p }))
	}
	if os.Getenv("JAVA_HOME") == "" {
		os.Setenv("JAVA_HOME", firstExisting(
			[]string{"/usr/lib/jvm/java-21-openjdk-amd64"}, func() string { return "" }))
	}
	// Same class of failure as a missing symbolizer, and just as silent. Ubuntu
	// ships DEBUGINFOD_URLS=https://debuginfod.ubuntu.com by default; the graded
	// harnesses have no outbound network, so EVERY llvm-symbolizer call blocks
	// ~90s on the debuginfod lookup, which blows the per-bug harness timeout —
	// ASan gets its "ERROR:" line out but is killed before printing a single
	// "#N file:line" frame, so class/crash fire while site/reach do not
	// (vuln_exit 124). We never want debuginfod here: the binaries being graded
	// carry their own DWARF. Force it off unconditionally.
	os.Setenv("DEBUGINFOD_URLS", "")
	fmt.Fprintf(os.Stderr, "grade-core: symbolizer=%q java=%q rounds=%s\n",
		os.Getenv("ASAN_SYMBOLIZER_PATH"), os.Getenv("JAVA_HOME"), os.Getenv("BENCH_GRADE_ROUNDS"))
	// An explicit -rounds overrides the default policy above.
	if *rounds > 0 {
		os.Setenv("BENCH_GRADE_ROUNDS", fmt.Sprintf("%d", *rounds))
	}

	// toolGrade requires the candidate to live under workspace. Stage a private
	// workspace and copy the input in, mirroring the grade server's per-request
	// temp workspace exactly.
	ws, err := os.MkdirTemp("", "gradecore-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "grade-core: workspace: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(ws)

	data, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "grade-core: read input: %v\n", err)
		os.Exit(1)
	}
	candidate := filepath.Join(ws, "candidate.bin")
	if err := os.WriteFile(candidate, data, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "grade-core: write candidate: %v\n", err)
		os.Exit(1)
	}

	s := &server{bugDir: *oracleDir, workspace: ws, oracleDir: *oracleDir}
	args, _ := json.Marshal(gradeParams{Path: candidate})
	res, err := s.toolGrade(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "grade-core: grade: %v\n", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		fmt.Fprintf(os.Stderr, "grade-core: encode: %v\n", err)
		os.Exit(1)
	}
}
