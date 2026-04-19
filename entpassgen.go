// Package main implements entpassgen — an entropy-focused password generator
// that uses crypto/rand for all randomness and supports both character-based
// and word-based password generation.
//
// # Usage
//
//	entpassgen [flags]
//
// Run entpassgen -h for the full flag reference.
package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ============================================================
// Embedded assets
// ============================================================

//go:embed data/words-english.txt
var englishBytes []byte

// versionBytes holds the raw contents of the VERSION file, embedded at
// compile time. Trimmed of whitespace by Version().
//
//go:embed VERSION
var versionBytes []byte

// Version returns the build version string embedded from the VERSION file.
// It is safe to call from multiple goroutines.
func Version() string {
	return strings.TrimSpace(string(versionBytes))
}

// ============================================================
// CLI flags — collected here so every default is visible in one place.
// ============================================================

var (
	length        int
	cores         int
	quantity      int
	passwordCount int

	generateAverage bool
	skipUppercase   bool
	skipLowercase   bool
	skipSymbols     bool
	skipDigits      bool
	useWords        bool
	showJSON        bool
	showVersion     bool

	outputFilePath string
	wordSeparators string
	symbols        string
	excludeSymbols string
	minEntropy     string

	// Character class constants — defined as vars so tests can reset them.
	acceptableUppercase      = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	acceptableLowercase      = "abcdefghijklmnopqrstuvwxyz"
	acceptableDigits         = "0123456789"
	acceptableWordSeparators = "!@#$%^&*()_+1234567890-=,.></?;:[]|"
	acceptableSymbols        = "!@#$%^&*()_+=-[]\\{}|;':,./<>?"

	stdOutTEXTFile *os.File
)

func init() {
	flag.IntVar(&cores, "c", -1, "Concurrency goroutines to use for generating samples over 10K (-1 = max)")
	flag.IntVar(&length, "l", -1, "Character length in new password (default: 17 chars, or 5 words with -w)")
	flag.IntVar(&quantity, "q", 1, "Quantity of passwords to generate")
	flag.IntVar(&passwordCount, "k", 100_000, "Sample size when computing average entropy (-a or -e avg)")
	flag.BoolVar(&useWords, "w", false, "Use words instead of characters (ignores -U -L -S -E -N -s)")
	flag.BoolVar(&showJSON, "j", false, "JSON formatted output")
	flag.BoolVar(&skipDigits, "N", false, "Do not use digits in new password")
	flag.BoolVar(&skipSymbols, "S", false, "Do not use symbols in new password")
	flag.BoolVar(&skipLowercase, "L", false, "Do not use lowercase characters in new password")
	flag.BoolVar(&skipUppercase, "U", false, "Do not use uppercase characters in new password")
	flag.BoolVar(&generateAverage, "a", false, "Report average, min, max and recommended entropy for the current options")
	flag.BoolVar(&showVersion, "v", false, "Print version and exit")
	flag.StringVar(&symbols, "s", acceptableSymbols, "Acceptable symbol characters")
	flag.StringVar(&excludeSymbols, "E", "", "Characters to exclude from the password")
	flag.StringVar(&minEntropy, "e", "avg",
		"Minimum Shannon entropy score to accept.\n"+
			"    Special values: 'avg' = compute average from -k samples, then use it as floor.\n"+
			"    Shorthand: n0–n9 = 90–99, e0–e9 = 80–89, s0–s9 = 70–79\n"+
			"    Example: -e n5 sets the floor to 95.0")
	flag.StringVar(&outputFilePath, "o", "", "Write output to this file instead of stdout")
	flag.StringVar(&wordSeparators, "W", acceptableWordSeparators, "Characters used to separate words (-w mode)")
}

// ============================================================
// Domain types
// ============================================================

// Password holds all metadata and the final value for a generated password.
type Password struct {
	Length    int64   `json:"length,omitempty"`
	Uppercase bool    `json:"uppercase,omitempty"`
	Lowercase bool    `json:"lowercase,omitempty"`
	Digits    bool    `json:"digits,omitempty"`
	Symbols   bool    `json:"symbols,omitempty"`
	Words     bool    `json:"words,omitempty"`
	Value     string  `json:"value,omitempty"`
	Sample    *Sample `json:"sample,omitempty"`
	Entropy   Entropy `json:"entropy,omitempty"`
}

// Entropy holds the Shannon entropy score for an accepted password and
// carries the resolved minimum-entropy threshold used during generation.
//
// NOTE on what this score means: the Score field is the Shannon-derived
// value −H(X)·L, where H(X) is per-character entropy and L is length.
// It measures character-distribution uniformity within the password string,
// NOT cryptographic search-space strength. Search-space strength for a
// random draw from a charset of size C at length L is log₂(Cᴸ) — a fixed
// value that is independent of the actual characters chosen.  The Shannon
// score is useful for detecting poorly-distributed generators; it is not a
// substitute for proper search-space analysis.
type Entropy struct {
	Score float64 `json:"score,omitempty"`
}

// Sample holds statistics gathered by calculateAverageEntropy.
type Sample struct {
	Limit       int64   `json:"limit,omitempty"`
	Average     float64 `json:"average,omitempty"`
	Recommended float64 `json:"recommended,omitempty"`
	Min         float64 `json:"min,omitempty"`
	Max         float64 `json:"max,omitempty"`
}

// ============================================================
// PasswordStore — thread-safe, ordered, deduplicated password collection.
// ============================================================

// PasswordStore stores unique passwords in insertion order.
// All methods are safe for concurrent use.
type PasswordStore struct {
	mu    sync.Mutex
	seen  map[string]struct{}
	items []Password
}

// NewPasswordStore returns an initialised, empty PasswordStore.
func NewPasswordStore() *PasswordStore {
	return &PasswordStore{
		seen:  make(map[string]struct{}),
		items: make([]Password, 0),
	}
}

// Add attempts to insert p into the store.
// Returns true if the password was new and was added.
// Returns false if the password value already exists (duplicate); the caller
// should retry with a different password in that case.
func (ps *PasswordStore) Add(p Password) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if _, exists := ps.seen[p.Value]; exists {
		return false
	}
	ps.seen[p.Value] = struct{}{}
	ps.items = append(ps.items, p)
	return true
}

// Len returns the number of unique passwords currently held.
func (ps *PasswordStore) Len() int {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return len(ps.items)
}

// Items returns a copy of the stored passwords in insertion order.
// Mutating the returned slice does not affect the store.
func (ps *PasswordStore) Items() []Password {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	out := make([]Password, len(ps.items))
	copy(out, ps.items)
	return out
}

// ============================================================
// Output helpers
// ============================================================

// PrintJSON marshals v to JSON and writes it to w.
// Calls log.Fatalf on marshal failure (indicates a programming error).
func PrintJSON(in interface{}, w io.Writer) {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatalf("PrintJSON: marshal failed: %v", err)
	}
	fmt.Fprintf(w, "%s", b)
}

// AsJSON marshals v to a JSON string and returns it.
// Calls log.Fatalf on marshal failure.
func AsJSON(in interface{}) string {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatalf("AsJSON: marshal failed: %v", err)
	}
	return string(b)
}

// DeliverResults writes the contents of store to w.
// A single password is written without a trailing newline (suitable for
// piping). Multiple passwords are each written on their own line.
// When showJSON is true, output is JSON instead of plain text.
func DeliverResults(store *PasswordStore, w io.Writer) {
	items := store.Items()
	if len(items) == 1 {
		if showJSON {
			PrintJSON(items[0], w)
		} else {
			fmt.Fprint(w, items[0].Value)
		}
	} else {
		if showJSON {
			PrintJSON(items, w)
		} else {
			for _, p := range items {
				fmt.Fprintf(w, "%s\n", p.Value)
			}
		}
	}
}

// ============================================================
// Validation
// ============================================================

// maxQuantity is the upper bound for the -q flag.
// The value 434 is an easter egg (machine elves), kept for continuity.
const maxQuantity = 434

// maxRetries is the maximum number of generation attempts in run() before
// giving up. Prevents an infinite loop when the entropy floor is set
// higher than any password of the chosen length and charset can achieve.
const maxRetries = 10_000_000

// validateConfig checks all preconditions on the current global flag values.
// Separated from ValidateRuntime so tests can call it without flag.Parse().
func validateConfig() error {
	if length == -1 {
		if useWords {
			length = 5
		} else {
			length = 17
		}
	}
	if length < 3 {
		return fmt.Errorf("invalid length -l %d (minimum 3)\n", length)
	}
	if quantity <= 0 {
		return fmt.Errorf("invalid quantity -q %d (must be > 0)\n", quantity)
	}
	if quantity > maxQuantity {
		return fmt.Errorf("invalid quantity -q %d (maximum %d)\n", quantity, maxQuantity)
	}
	if passwordCount > 1_000_000_001 {
		return fmt.Errorf("invalid sample size -k %d (maximum 1,000,000,001)\n", passwordCount)
	}
	if skipUppercase && skipLowercase && skipSymbols && skipDigits {
		return fmt.Errorf("%s", "cannot generate password: all character classes are disabled\n")
	}
	return nil
}

// ValidateRuntime parses CLI flags and enforces preconditions.
// It calls log.Fatalf (which exits) on any invalid combination.
func ValidateRuntime() {
	flag.Parse()
	if showVersion {
		fmt.Printf("entpassgen %s\n", Version())
		os.Exit(0)
	}
	err := validateConfig()
	if err != nil {
		log.Fatal(err)
	}
}

// ============================================================
// Entropy
// ============================================================

// ParseEntropy resolves the package-level minEntropy string to a concrete
// float-formatted string.  It handles three cases:
//
//  1. "avg" — replaced with the formatted average from password.Sample.
//  2. Shorthand tokens (n0–n9, e0–e9, s0–s9) — expanded to numeric strings.
//  3. Any other value — left unchanged (validated later by parseEntropy).
func (p *Password) ParseEntropy() {
	p.Entropy.parse(p)
}

// parse is the unexported implementation called by ParseEntropy.
func (e *Entropy) parse(password *Password) {
	if minEntropy == "avg" {
		minEntropy = fmt.Sprintf("%.3f", password.Sample.Average)
		return
	}

	// Shorthand entropy selectors.
	// Format: <letter><digit>
	//   n0–n9 → 90.0–99.0  (nine-ty range)
	//   e0–e9 → 80.0–89.0  (eight-y range)
	//   s0–s9 → 70.0–79.0  (seven-ty range)
	letterToBase := map[byte]int{
		'n': 90,
		'e': 80,
		's': 70,
	}
	if len(minEntropy) == 2 {
		letter := minEntropy[0]
		digit := minEntropy[1]
		if base, ok := letterToBase[letter]; ok && digit >= '0' && digit <= '9' {
			value := float64(base) + float64(digit-'0')
			minEntropy = fmt.Sprintf("%.1f", value)
		}
	}
}

// calculateEntropy returns a Shannon-derived entropy score for the given
// password string: −H(X)·L, where H(X) is the per-character Shannon entropy
// and L is the string length.
//
// Interpretation:
//   - Returns 0 for an empty string or a string with only one unique character.
//   - Higher values indicate greater character-distribution uniformity.
//   - This is NOT a measure of brute-force resistance. Search-space entropy
//     for a randomly generated password is log₂(charsetSize^length), which
//     is independent of which characters were chosen.
func calculateEntropy(password string) float64 {
	l := len(password)
	if l == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, ch := range password {
		freq[ch]++
	}
	var h float64
	for _, count := range freq {
		p := count / float64(l)
		h += p * math.Log2(p)
	}
	return -h * float64(l)
}

// parseEntropy converts the minEntropy string to a float64 threshold.
// "avg" returns 0.0 (the threshold will have been resolved earlier by
// ParseEntropy; "avg" reaching here means no sample was run, so accept all).
// Any non-numeric value causes log.Fatalf.
func parseEntropy(entropy string) float64 {
	if entropy == "avg" || entropy == "0" {
		return 0.0
	}
	var value float64
	if _, err := fmt.Sscanf(entropy, "%f", &value); err != nil {
		log.Fatalf("invalid entropy value %q: %v\n", entropy, err)
	}
	if math.IsNaN(value) || math.IsInf(value, 0) {
		log.Fatalf("invalid entropy value %q: must be a finite number\n", entropy)
	}
	return value
}

// ============================================================
// Cryptographic randomness
// ============================================================

// randomInt returns a cryptographically secure random integer in [0, max).
// Uses crypto/rand.Int with math/big to eliminate modulo bias.
// Calls log.Fatalf if max <= 0 or if the underlying RNG fails.
func randomInt(max int) int {
	if max <= 0 {
		log.Fatalf("randomInt: max must be > 0, got %d", max)
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		log.Fatalf("randomInt: crypto/rand failed: %v", err)
	}
	return int(n.Int64())
}

// ============================================================
// Password generation
// ============================================================

// generateRandomPassword generates a random character-based password of the
// given length by drawing uniformly from the active character set.
//
// The charset is built from the enabled character classes (uppercase,
// lowercase, digits, symbols) with excludeSymbols removed.
// Returns an error if the resulting charset is empty.
func generateRandomPassword(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("generateRandomPassword: length must be > 0, got %d", length)
	}

	charset := ""
	if !skipUppercase {
		charset += acceptableUppercase
	}
	if !skipLowercase {
		charset += acceptableLowercase
	}
	if !skipDigits {
		charset += acceptableDigits
	}
	if !skipSymbols {
		charset += symbols
	}
	for _, c := range excludeSymbols {
		charset = strings.ReplaceAll(charset, string(c), "")
	}
	if len(charset) == 0 {
		return "", errors.New("generateRandomPassword: charset is empty after applying exclusions — enable at least one character class")
	}

	result := make([]byte, length)
	total := len(charset)
	for i := range result {
		result[i] = charset[randomInt(total)]
	}
	return string(result), nil
}

// ============================================================
// Word-based generation
// ============================================================

var (
	acceptableWords []string
	wordsOnce       sync.Once
	wordsErr        error
)

// loadWords populates acceptableWords from the embedded English word list.
// Only words longer than 5 characters are included.
// Safe to call concurrently; the underlying work runs exactly once.
func loadWords() error {
	wordsOnce.Do(func() {
		all := strings.Split(string(englishBytes), "\n")
		for _, w := range all {
			w = strings.TrimSpace(w)
			if len(w) > 5 {
				acceptableWords = append(acceptableWords, w)
			}
		}
		if len(acceptableWords) == 0 {
			wordsErr = errors.New("loadWords: no words loaded from embedded word list")
		}
	})
	return wordsErr
}

// generateWordPassword generates a password composed of wordCount random
// English words separated by a randomly chosen character from wordSeparators
// (minus any excludeSymbols).
// Returns an error if the word list cannot be loaded or the separator set
// becomes empty after exclusions.
func generateWordPassword(wordCount int) (string, error) {
	if err := loadWords(); err != nil {
		return "", err
	}

	seps := wordSeparators
	if seps == "" {
		seps = acceptableWordSeparators
	}
	for _, c := range excludeSymbols {
		seps = strings.ReplaceAll(seps, string(c), "")
	}
	if len(seps) == 0 {
		return "", errors.New("generateWordPassword: separator set is empty after applying exclusions")
	}

	total := len(acceptableWords)
	words := make([]string, wordCount)
	for i := range words {
		words[i] = acceptableWords[randomInt(total)]
	}

	var sb strings.Builder
	for i, word := range words {
		sb.WriteString(word)
		if i < len(words)-1 {
			sb.WriteByte(seps[randomInt(len(seps))])
		}
	}
	return sb.String(), nil
}

// ============================================================
// Concurrency helpers
// ============================================================

// intparts splits total into chunks of size partSize.
// If partSize <= 0 the entire total is returned as a single chunk
// to prevent division-by-zero or infinite loops.
func intparts(total, partSize int) []int {
	if partSize <= 0 {
		return []int{total}
	}
	var parts []int
	for total > 0 {
		if total > partSize {
			parts = append(parts, partSize)
			total -= partSize
		} else {
			parts = append(parts, total)
			total = 0
		}
	}
	return parts
}

// ============================================================
// Entropy sampling
// ============================================================

// calculateAverageEntropy generates count passwords using the current settings,
// computes their Shannon entropy scores, and returns (average, min, max, recommended).
// recommended = (average + max) / 2.
//
// Work is distributed across goroutines; the number of goroutines is controlled
// by the -c flag (default: GOMAXPROCS). A spinner is printed to stderr for runs
// that take longer than 11 seconds, so stdout remains clean for piping.
func calculateAverageEntropy(count int) (avg, minEnt, maxEnt, recommended float64) {
	var (
		totalEntropy float64
		localMin     = math.MaxFloat64
		localMax     float64
		mu           sync.Mutex
		wg           sync.WaitGroup
	)

	coresToUse := cores
	if coresToUse == -1 {
		coresToUse = runtime.GOMAXPROCS(0)
	}
	if coresToUse < 1 {
		coresToUse = 1
	}

	chunks := intparts(count, count/coresToUse)

	// done is closed (not sent on) so that all goroutines selecting on it
	// receive the signal simultaneously, regardless of how many were started.
	done := make(chan struct{})
	startTime := time.Now()

	// Monitor elapsed time; start the spinner only for long-running jobs.
	var monitorWg sync.WaitGroup
	monitorWg.Add(1)
	go func() {
		defer monitorWg.Done()
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if time.Since(startTime) > 11*time.Second {
					go showSpinner(startTime, done)
					return
				}
			}
		}
	}()

	for _, chunk := range chunks {
		chunk := chunk
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			var lTotal, lMin, lMax float64
			lMin = math.MaxFloat64
			for i := 0; i < n; i++ {
				var pw string
				var err error
				if useWords {
					pw, err = generateWordPassword(length)
				} else {
					pw, err = generateRandomPassword(length)
				}
				if err != nil {
					log.Printf("calculateAverageEntropy: generation error: %v", err)
					continue
				}
				e := calculateEntropy(pw)
				lTotal += e
				if e < lMin {
					lMin = e
				}
				if e > lMax {
					lMax = e
				}
			}
			mu.Lock()
			totalEntropy += lTotal
			if lMin < localMin {
				localMin = lMin
			}
			if lMax > localMax {
				localMax = lMax
			}
			mu.Unlock()
		}(chunk)
	}

	wg.Wait()
	close(done)      // broadcast to monitor + any spinner goroutine
	monitorWg.Wait() // ensure monitor exits before we return
	clearLine()

	avg = totalEntropy / float64(count)
	recommended = (avg + localMax) / 2
	return avg, localMin, localMax, recommended
}

// ============================================================
// Spinner — always writes to stderr so stdout stays clean.
// ============================================================

// clearLine erases the current terminal line on stderr.
func clearLine() {
	fmt.Fprint(os.Stderr, "\r\033[2K")
}

// showSpinner prints an animated progress indicator to stderr until done is
// closed. It is launched as a goroutine by calculateAverageEntropy.
func showSpinner(startTime time.Time, done <-chan struct{}) {
	spinner := []string{"|", "/", "-", "\\"}
	i := 0
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			clearLine()
			return
		case <-ticker.C:
			elapsed := time.Since(startTime).Seconds()
			fmt.Fprintf(os.Stderr, "\r\033[1;34mCalculating ... %.1fs %s\033[0m",
				elapsed, spinner[i%len(spinner)])
			i++
		}
	}
}

// ============================================================
// Core generation loop
// ============================================================

// run generates passwords until store holds quantity unique entries, each
// meeting the minEntropy threshold. It retries up to maxRetries times before
// giving up with a fatal error — preventing an infinite loop when the entropy
// floor is set higher than any password of the chosen length can achieve.
func run(password *Password, store *PasswordStore) {
	threshold := parseEntropy(minEntropy)
	if password.Sample.Max > 0 && threshold > password.Sample.Max {
		log.Fatalf(
			"entropy floor %.1f is unreachable at length %d.\n"+
				"Observed maximum across %d samples: %.3f.\n"+
				"Lower -e or increase -l.",
			threshold, length, passwordCount, password.Sample.Max,
		)
	}
	attempts := 0

	for store.Len() < quantity {
		attempts++
		if attempts > maxRetries {
			log.Fatalf(
				"run: could not find a password meeting entropy threshold %.3f after %d attempts.\n"+
					"Try a lower -e value or a longer -l length.",
				threshold, maxRetries,
			)
		}

		var (
			pw  string
			err error
		)
		if useWords {
			pw, err = generateWordPassword(length)
		} else {
			pw, err = generateRandomPassword(length)
		}
		if err != nil {
			log.Printf("run: generation error: %v", err)
			continue
		}

		e := calculateEntropy(pw)
		if e >= threshold {
			p := *password
			p.Value = pw
			p.Entropy.Score = e
			store.Add(p) // false return means duplicate — just try again
		}
	}
}

// ============================================================
// Entropy report
// ============================================================

// printEntropyReport writes a human-readable entropy analysis to stderr.
// Called when -a is set; stderr keeps stdout clean for piping.
// printEntropyReport writes a human-readable entropy analysis to w.
// In main(), w is os.Stderr. In tests, w is a bytes.Buffer.
func printEntropyReport(s *Sample, w io.Writer) {
	fmt.Fprintf(w, "\nEntropy Report:\n")
	fmt.Fprintf(w, "  Samples:     %d\n", s.Limit)
	fmt.Fprintf(w, "  Length:      %d\n", length)
	fmt.Fprintf(w, "  Uppercase:   %v\n", !skipUppercase)
	fmt.Fprintf(w, "  Lowercase:   %v\n", !skipLowercase)
	fmt.Fprintf(w, "  Digits:      %v\n", !skipDigits)
	fmt.Fprintf(w, "  Symbols:     %v\n", !skipSymbols)
	fmt.Fprintf(w, "  Use Words:   %v\n", useWords)
	fmt.Fprintf(w, "  Average:     %.3f\n", s.Average)
	fmt.Fprintf(w, "  Minimum:     %.3f\n", s.Min)
	fmt.Fprintf(w, "  Maximum:     %.3f\n", s.Max)
	fmt.Fprintf(w, "  Recommended: %.3f\n\n", s.Recommended)
}

// ============================================================
// Main
// ============================================================

func main() {
	ValidateRuntime()

	password := Password{
		Length:    int64(length),
		Uppercase: !skipUppercase,
		Lowercase: !skipLowercase,
		Digits:    !skipDigits,
		Symbols:   !skipSymbols,
		Words:     useWords,
		Entropy:   Entropy{},
		Sample: &Sample{
			Limit: int64(passwordCount),
		},
	}

	// Run entropy sampling if requested or if the floor is "avg".
	if generateAverage || minEntropy == "avg" {
		password.Sample.Average,
			password.Sample.Min,
			password.Sample.Max,
			password.Sample.Recommended = calculateAverageEntropy(passwordCount)
	}

	password.ParseEntropy()

	if generateAverage {
		printEntropyReport(password.Sample, os.Stderr)
	}

	// Open output destination.
	var err error
	if len(outputFilePath) > 0 {
		stdOutTEXTFile, err = os.OpenFile(
			outputFilePath,
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
			0600,
		)
		if err != nil {
			log.Fatalf("cannot open output file %q: %v", outputFilePath, err)
		}
		defer stdOutTEXTFile.Close()
	} else {
		stdOutTEXTFile = os.Stdout
	}

	store := NewPasswordStore()
	run(&password, store)

	// For JSON output, write to a secure temp file first then copy to the
	// final destination. This prevents a partial JSON blob appearing on
	// stdout if the process is interrupted mid-write.
	if showJSON {
		tmpName := fmt.Sprintf("entpassgen.%d.json", time.Now().UnixNano())
		tmpPath := filepath.Join(os.TempDir(), tmpName)
		tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, 0600)
		if err != nil {
			log.Fatalf("cannot create JSON temp file: %v", err)
		}
		defer func() {
			tmpFile.Close()
			os.Remove(tmpPath)
		}()
		DeliverResults(store, tmpFile)
		if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
			log.Fatalf("cannot seek JSON temp file: %v", err)
		}
		if _, err := io.Copy(stdOutTEXTFile, tmpFile); err != nil {
			log.Fatalf("cannot copy JSON output: %v", err)
		}
		return
	}

	DeliverResults(store, stdOutTEXTFile)
}
