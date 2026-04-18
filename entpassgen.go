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

//go:embed data/words-english.txt
var englishBytes []byte

var (
	length                   int
	cores                    int
	quantity                 int
	generateAverage          bool
	passwordCount            int
	skipUppercase            bool
	skipLowercase            bool
	skipSymbols              bool
	skipDigits               bool
	useWords                 bool
	outputFilePath           string
	wordSeparators           string
	showJSON                 bool
	acceptableUppercase      string = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	acceptableLowercase      string = "abcdefghijklmnopqrstuvwxyz"
	acceptableDigits         string = "0123456789"
	acceptableWordSeparators string = "!@#$%^&*()_+1234567890-=,.></?;:[]|"
	acceptableSymbols        string = "!@#$%^&*()_+=-[]\\{}|;':,./<>?"
	symbols                  string
	excludeSymbols           string
	minEntropy               string
	stdOutTEXTFile           *os.File
	stdOutJSONFile           *os.File
)

func init() {
	flag.IntVar(&cores, "c", -1, "Concurrency goroutines to use for generating samples over 10K (-1 = max)")
	flag.IntVar(&length, "l", 12, "Character length in new password")
	flag.IntVar(&quantity, "q", 1, "Quantity of passwords to generate (default = 1)")
	flag.BoolVar(&useWords, "w", false, "Use words (ignores -U -L -S -E -N -s)")
	flag.BoolVar(&showJSON, "j", false, "JSON formatted output")
	flag.StringVar(&symbols, "s", acceptableSymbols, "Define acceptable symbols in new password")
	flag.BoolVar(&skipDigits, "N", false, "Do not use numbers in new password")
	flag.BoolVar(&skipSymbols, "S", false, "Do not use symbols in new password")
	flag.StringVar(&minEntropy, "e", "avg", "Minimum entropy value to accept in new password")
	flag.IntVar(&passwordCount, "k", 100_000, "Quantity of passwords to generate when calculating average entropy")
	flag.BoolVar(&skipLowercase, "L", false, "Do not use lowercase characters in new password")
	flag.BoolVar(&skipUppercase, "U", false, "Do not use uppercase characters in new password")
	flag.BoolVar(&generateAverage, "a", false, "Generate new passwords to get average entropy, min entropy and max entropy calculated for options")
	flag.StringVar(&outputFilePath, "o", "", "Path to write output instead of STDOUT")
	flag.StringVar(&wordSeparators, "W", acceptableWordSeparators, "Separate words with these possible characters")
	flag.StringVar(&excludeSymbols, "E", "", "Define exclude symbols in new password")
}

// ============================================================
// Types
// ============================================================

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

type Entropy struct {
	Score float64 `json:"score,omitempty"`
}

type Sample struct {
	Limit       int64   `json:"limit,omitempty"`
	Average     float64 `json:"average,omitempty"`
	Recommended float64 `json:"recommended,omitempty"`
	Min         float64 `json:"min,omitempty"`
	Max         float64 `json:"max,omitempty"`
}

// PasswordStore replaces the map[string]Password pattern.
// Using the password value as a map key caused silent deduplication,
// heap-lingering strings, and made collision detection invisible to
// the caller. PasswordStore makes uniqueness enforcement explicit and
// auditable — the caller sees false on collision and retries.
type PasswordStore struct {
	mu    sync.Mutex
	seen  map[string]struct{}
	items []Password
}

func NewPasswordStore() *PasswordStore {
	return &PasswordStore{
		seen:  make(map[string]struct{}),
		items: make([]Password, 0),
	}
}

// Add attempts to add a password to the store.
// Returns true if added, false if the value was already present.
// The caller is responsible for retrying on false.
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

// Len returns the number of unique passwords stored.
func (ps *PasswordStore) Len() int {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return len(ps.items)
}

// Items returns a copy of the stored passwords in insertion order.
func (ps *PasswordStore) Items() []Password {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	out := make([]Password, len(ps.items))
	copy(out, ps.items)
	return out
}

// ============================================================
// Output
// ============================================================

func PrintJSON(in interface{}, w io.Writer) {
	jsonBytes, err := json.Marshal(in)
	if err != nil {
		log.Fatalf("failed to marshal to JSON: %v", err)
	}
	fmt.Fprintf(w, "%s", string(jsonBytes))
}

func AsJSON(in interface{}) string {
	jsonBytes, err := json.Marshal(in)
	if err != nil {
		log.Fatalf("failed to marshal to JSON: %v", err)
	}
	return string(jsonBytes)
}

// DeliverResults writes passwords from store to w.
// Accepts an io.Writer so output can be redirected in tests
// without touching global file handles.
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

func ValidateRuntime() {
	flag.Parse()

	if length == -1 {
		if useWords {
			length = 5
		} else {
			length = 17
		}
	}

	if length < 3 {
		log.Fatalf("invalid length -l %d\n", length)
	}

	if quantity < 0 {
		log.Fatalf("invalid quantity -q %d\n", quantity)
	}

	// 434: machine elves — they help with the entropy
	if quantity >= 434 {
		log.Fatalf("invalid quantity (max 434) -q %d\n", quantity)
	}

	if passwordCount > 1_000_000_001 {
		log.Fatalf("invalid limit (max 1B) -k %d\n", passwordCount)
	}

	if skipUppercase && skipLowercase && skipSymbols && skipDigits {
		log.Fatal("can't generate password: all character classes disabled\n")
	}
}

// ============================================================
// Entropy
// ============================================================

func (p *Password) ParseEntropy() {
	p.Entropy.Parse(p)
}

func (e *Entropy) Parse(password *Password) {
	if minEntropy == "avg" {
		minEntropy = fmt.Sprintf("%.3f", password.Sample.Average)
		return
	}

	// Shorthand entropy selectors: n8=98, e8=88, s8=78 etc.
	// The letter sets the tens digit prefix, the number sets the units.
	// e.g. "n8" → "98.0", "e3" → "83.0", "s5" → "75.0"
	for _, letter := range "nes" {
		for i := 0; i < 10; i++ {
			if minEntropy == fmt.Sprintf("%s%d", string(letter), i) {
				tens := ""
				switch string(letter) {
				case "n":
					tens = "9"
				case "e":
					tens = "8"
				case "s":
					tens = "7"
				}
				digits := fmt.Sprintf("%s%d.0", tens, i)
				var value float64
				if _, err := fmt.Sscanf(digits, "%f", &value); err != nil {
					log.Fatalf("invalid entropy shorthand: %s → %s: %v\n", minEntropy, digits, err)
				}
				// Assign the resolved numeric string so parseEntropy
				// receives a valid float rather than the shorthand token.
				minEntropy = digits
				return
			}
		}
	}
}

func calculateEntropy(password string) float64 {
	length := len(password)
	if length == 0 {
		return 0
	}
	frequency := make(map[rune]float64)
	for _, char := range password {
		frequency[char]++
	}
	var entropy float64
	for _, count := range frequency {
		p := count / float64(length)
		entropy += p * math.Log2(p)
	}
	return -entropy * float64(length)
}

func parseEntropy(entropy string) float64 {
	if entropy == "avg" {
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
// Random
// ============================================================

// randomInt returns a cryptographically secure random integer in [0, max).
// Uses crypto/rand.Int with math/big to eliminate modulo bias — the
// approach recommended by security practitioners over single-byte % max.
func randomInt(max int) int {
	if max <= 0 {
		log.Fatalf("randomInt: max must be greater than zero, got %d", max)
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

func generateRandomPassword(length int) string {
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
	if excludeSymbols != "" {
		for _, c := range excludeSymbols {
			charset = strings.ReplaceAll(charset, string(c), "")
		}
	}
	if len(charset) == 0 {
		log.Fatal("generateRandomPassword: charset is empty after applying exclusions — enable at least one character class")
	}
	result := make([]byte, length)
	total := len(charset)
	for i := range result {
		result[i] = charset[randomInt(total)]
	}
	return string(result)
}

var acceptableWords []string

func loadWords() error {
	if len(acceptableWords) > 50 {
		return nil
	}
	words := strings.Split(string(englishBytes), "\n")
	for _, word := range words {
		word = strings.TrimSpace(word)
		if len(word) > 5 {
			acceptableWords = append(acceptableWords, word)
		}
	}
	if len(acceptableWords) == 0 {
		return errors.New("no words imported into memory")
	}
	return nil
}

func generateWordPassword(wordCount int) (string, error) {
	if err := loadWords(); err != nil {
		return "", err
	}

	// Use the -W flag value so the user-supplied separator set is respected.
	// Falls back to acceptableWordSeparators only if wordSeparators is empty.
	seps := wordSeparators
	if seps == "" {
		seps = acceptableWordSeparators
	}
	if excludeSymbols != "" {
		for _, c := range excludeSymbols {
			seps = strings.ReplaceAll(seps, string(c), "")
		}
	}
	if len(seps) == 0 {
		return "", errors.New("generateWordPassword: separator set is empty after applying exclusions")
	}

	totalWords := len(acceptableWords)
	words := make([]string, wordCount)
	for i := range words {
		words[i] = acceptableWords[randomInt(totalWords)]
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
// Concurrency
// ============================================================

// intparts splits i into chunks of size p.
// Returns []int{i} if p <= 0 to prevent infinite loops and
// division-by-zero in calculateAverageEntropy.
func intparts(i, p int) []int {
	if p <= 0 {
		return []int{i}
	}
	var parts []int
	for i > 0 {
		if i > p {
			parts = append(parts, p)
			i -= p
		} else {
			parts = append(parts, i)
			i = 0
		}
	}
	return parts
}

func calculateAverageEntropy(count int) (float64, float64, float64, float64) {
	var totalEntropy float64
	minEnt := math.MaxFloat64
	var maxEnt float64
	var mu sync.Mutex

	coresToUse := cores
	if coresToUse == -1 {
		coresToUse = runtime.GOMAXPROCS(0)
	}
	if coresToUse < 1 {
		coresToUse = 1
	}

	chunks := intparts(count, count/coresToUse)
	startTime := time.Now()
	done := make(chan bool, 1)

	// Monitor elapsed time and start the spinner only for long runs.
	// Uses time.NewTicker so the ticker can be stopped and the goroutine
	// exits cleanly — avoiding the time.Tick leak on short runs.
	go func() {
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

	var wg sync.WaitGroup
	for _, chunk := range chunks {
		chunk := chunk
		wg.Add(1)
		go func(chunk int) {
			defer wg.Done()
			var localTotal, localMin, localMax float64
			localMin = math.MaxFloat64
			for i := 0; i < chunk; i++ {
				var pw string
				if useWords {
					var err error
					pw, err = generateWordPassword(length)
					if err != nil {
						log.Printf("generateWordPassword error: %v", err)
						continue
					}
				} else {
					pw = generateRandomPassword(length)
				}
				e := calculateEntropy(pw)
				localTotal += e
				if e < localMin {
					localMin = e
				}
				if e > localMax {
					localMax = e
				}
			}
			mu.Lock()
			totalEntropy += localTotal
			if localMin < minEnt {
				minEnt = localMin
			}
			if localMax > maxEnt {
				maxEnt = localMax
			}
			mu.Unlock()
		}(chunk)
	}
	wg.Wait() // outside the loop — all goroutines run concurrently

	done <- true
	clearLine()

	avg := totalEntropy / float64(count)
	recommended := (avg + maxEnt) / 2
	return avg, minEnt, maxEnt, recommended
}

// ============================================================
// Spinner — writes to stderr so stdout stays clean for password output.
// Piping works correctly: entpassgen -a | grep value won't capture noise.
// ============================================================

func clearLine() {
	fmt.Fprint(os.Stderr, "\r\033[2K")
}

func showSpinner(startTime time.Time, done chan bool) {
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
// Run
// ============================================================

func run(password *Password, store *PasswordStore) {
	for {
		var pw string
		if useWords {
			var err error
			pw, err = generateWordPassword(length)
			if err != nil {
				log.Printf("generateWordPassword error: %v", err)
				continue
			}
		} else {
			pw = generateRandomPassword(length)
		}

		e := calculateEntropy(pw)
		if e >= parseEntropy(minEntropy) {
			p := *password
			p.Value = pw
			p.Entropy.Score = e
			if store.Add(p) && store.Len() >= quantity {
				break
			}
		}
	}
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

	if generateAverage || minEntropy == "avg" {
		password.Sample.Average,
			password.Sample.Min,
			password.Sample.Max,
			password.Sample.Recommended = calculateAverageEntropy(passwordCount)
	}

	password.ParseEntropy()

	// Determine text output destination.
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

	// JSON temp file: permissions set to 0600 before any password
	// data is written. filepath.Join used for cross-platform safety.
	if showJSON {
		tmpName := fmt.Sprintf("entpassgen.%d.json", time.Now().UnixNano())
		tmpPath := filepath.Join(os.TempDir(), tmpName)
		stdOutJSONFile, err = os.OpenFile(
			tmpPath,
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL,
			0600,
		)
		if err != nil {
			log.Fatalf("cannot create JSON temp file: %v", err)
		}
		defer func() {
			stdOutJSONFile.Close()
			os.Remove(tmpPath)
		}()
	}

	store := NewPasswordStore()
	run(&password, store)

	// Write results to the appropriate destination.
	out := io.Writer(stdOutTEXTFile)
	if showJSON {
		out = stdOutJSONFile
	}
	DeliverResults(store, out)

	// Copy JSON temp file to final destination.
	if showJSON {
		if _, err := stdOutJSONFile.Seek(0, io.SeekStart); err != nil {
			log.Fatalf("cannot seek JSON temp file: %v", err)
		}
		if _, err := io.Copy(stdOutTEXTFile, stdOutJSONFile); err != nil {
			log.Fatalf("cannot copy JSON output: %v", err)
		}
	}
}
