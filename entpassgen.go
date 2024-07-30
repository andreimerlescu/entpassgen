package main

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
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
	showTEXT                 bool
	symbols                  string
	excludeSymbols           string
	minEntropy               string
	acceptableUppercase      string = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	acceptableLowercase      string = "abcdefghijklmnopqrstuvwxyz"
	acceptableDigits         string = "0123456789"
	acceptableWordSeparators string = "!@#$%^&*()_+1234567890-=,.></?;:[]|"
	acceptableSymbols        string = "!@#$%^&*()_+=-[]\\{}|;':,./<>?"
)

func init() {
	flag.IntVar(&cores, "c", -1, "Concurrency goroutines to use for generating samples over 10K (-1 = max)")
	flag.IntVar(&length, "l", -1, "Character length in new password")
	flag.IntVar(&quantity, "q", 1, "Quantity of passwords to generate (default = 1)")
	flag.BoolVar(&useWords, "w", false, "Use words (ignores -U -L -S -E -N -s)")
	flag.BoolVar(&showJSON, "j", false, "JSON formatted output")
	flag.BoolVar(&showTEXT, "t", true, "TEXT formatted output (default)")
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

func PrintJSON(in interface{}) {
	jsonBytes, jsonErr := json.Marshal(in)
	if jsonErr != nil {
		log.Fatalf("Can't marshal Entropy object. Error: %v", jsonErr)
	} else {
		fmt.Printf("%s", string(jsonBytes))
	}
}

func AsJSON(in interface{}) string {
	jsonBytes, jsonErr := json.Marshal(in)
	if jsonErr != nil {
		log.Fatalf("Can't marshal Entropy object. Error: %v", jsonErr)
	} else {
		return string(jsonBytes)
	}
	return ""
}

func DeliverResults(passwords map[string]Password, destination io.Writer) {
	var results []Password
	for _, p := range passwords {
		results = append(results, p)
	}
	if len(results) == 1 {
		if showJSON {
			fmt.Fprintf(destination, "%s\n", AsJSON(results[0]))
		} else {
			fmt.Fprintf(destination, results[0].Value)
		}
	} else {
		if showJSON {
			fmt.Fprintf(destination, "%s\n", AsJSON(results))
		} else {
			for _, p := range results {
				fmt.Fprintf(destination, "%s\n", p.Value)
			}
		}
	}
}

func redirectOutput(w io.Writer, done chan bool) (*os.File, error) {
	old := os.Stdout
	r, w2, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	os.Stdout = w2

	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		cleanedOutput := cleanOutput(buf.String())
		w.Write([]byte(cleanedOutput))
		done <- true
	}()
	return old, nil
}

func main() {
	flag.Parse()

	if length == -1 {
		if useWords {
			length = 5
		} else {
			length = 17
		}
	}

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

	if length < 3 {
		log.Fatalf("Invalid length -l %d.\n", length)
	}

	if quantity < 0 {
		log.Fatalf("Invalid quantity -q %d\n", quantity)
	}

	if quantity >= 434 {
		log.Fatalf("Invalid quantity (max 434) -q %d\n", quantity)
	}

	if passwordCount > 1_000_000_001 {
		log.Fatalf("Invalid limit (max 1B) -k %d\n", passwordCount)
	}

	if skipUppercase && skipLowercase && skipSymbols && skipDigits {
		log.Fatal("Can't generate password.\n")
	}

	if generateAverage || minEntropy == "avg" {
		password.Sample.Average, password.Sample.Min, password.Sample.Max, password.Sample.Recommended = calculateAverageEntropy(passwordCount)
	}

	if minEntropy == "avg" {
		minEntropy = fmt.Sprintf("%.3f", password.Sample.Average)
	}
	// allows -e n8 for 98% of password.Sample.Max entropy from sample
	for _, letter := range "nes" {
		for i := 0; i < 10; i++ {
			if minEntropy == fmt.Sprintf("%s%d", string(letter), i) {
				tens := ""
				if string(letter) == "n" {
					tens = "9"
				} else if string(letter) == "e" {
					tens = "8"
				} else if string(letter) == "s" {
					tens = "7"
				}
				digits := fmt.Sprintf("%s%d.0", tens, i)
				var value float64
				_, err := fmt.Sscanf(digits, "%f", &value)
				if err != nil {
					log.Fatalf("Invalid entropy value: %s\n", digits)
				}
			}
		}
	}

	if generateAverage {
		if showJSON {
			PrintJSON(password)
		} else {
			fmt.Println("Entropy Report: ")
			fmt.Printf("  Samples: %d\n", password.Sample.Limit)
			fmt.Printf("  Length: %d\n", password.Length)
			fmt.Printf("  Uppercase: %v\n", password.Uppercase)
			fmt.Printf("  Lowercase: %v\n", password.Lowercase)
			fmt.Printf("  Digits: %v\n", password.Digits)
			fmt.Printf("  Symbols: %v\n", password.Symbols)
			fmt.Printf("  Use Words: %v\n", password.Words)
			fmt.Printf("  Average: %0.3f\n", password.Sample.Average)
			fmt.Printf("  Minimum: %0.3f\n", password.Sample.Min)
			fmt.Printf("  Maximum: %0.3f\n", password.Sample.Max)
			fmt.Printf("  Recommended: %0.3f\n", password.Sample.Recommended)
		}
		return
	}

	var passwords = make(map[string]Password, 0)
	var destination io.Writer
	if len(outputFilePath) > 0 {
		var err error
		destination, err = os.Create(outputFilePath)
		if err != nil {
			log.Fatalf("cannot write to -o %v due to error %v", outputFilePath, err)
		}
	} else {
		destination = os.Stdout
	}

	// Create channels to manage spinner output and JSON output
	spinnerDone := make(chan bool)
	jsonDone := make(chan bool)

	// Redirect output for spinner
	oldStdout, err := redirectOutput(os.Stdout, spinnerDone)
	if err != nil {
		log.Fatalf("Failed to redirect stdout: %v", err)
	}

	// Run the spinner
	go func() {
		startTime := time.Now()
		showSpinner(startTime, spinnerDone)
	}()

	cleanedStdout := &cleanWriter{writer: destination}
	for {
		var newPassword string
		if useWords {
			var wordErr error
			newPassword, wordErr = generateWordPassword(length)
			if wordErr != nil {
				log.Printf("wordErr = %v", wordErr)
				continue
			}
		} else {
			newPassword = generateRandomPassword(length)
		}
		entropy := calculateEntropy(newPassword)
		parsedEntropy := parseEntropy(minEntropy)
		if entropy >= parsedEntropy {
			password.Value = newPassword
			password.Entropy.Score = entropy
			passwords[newPassword] = password
			if len(passwords) < quantity {
				continue
			}
			DeliverResults(passwords, cleanedStdout)
			break
		}
	}

	// Restore the original os.Stdout and signal spinner to stop
	os.Stdout = oldStdout
	spinnerDone <- true
	<-jsonDone
}

func generateWordPassword(wordCount int) (string, error) {
	loadErr := loadWords()
	if loadErr != nil {
		return "NO_PASSWORD", loadErr
	}
	totalWords := len(acceptableWords)
	words := make([]string, wordCount)
	for i := 0; i < wordCount; i++ {
		words[i] = acceptableWords[randomInt(totalWords)]
	}

	if excludeSymbols != "" {
		acceptableWordSeparators = strings.ReplaceAll(acceptableWordSeparators, excludeSymbols, "")
	}

	var sb = strings.Builder{}
	cnt := 0
	total := len(acceptableWordSeparators)
	for _, word := range words {
		cnt++
		separator := acceptableWordSeparators[randomInt(total)]
		if cnt == total {
			sb.WriteString(word)
		} else {
			sb.WriteString(word + string(separator))
		}
	}
	return sb.String(), nil
}

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

	result := make([]byte, length)
	total := len(charset)
	for i := range result {
		randomChar := charset[randomInt(total)]
		result[i] = randomChar
	}
	return string(result)
}

var acceptableWords []string

func loadWords() error {
	if len(acceptableWords) > 50 {
		return nil
	}
	wordsStr := string(englishBytes)
	words := strings.Split(wordsStr, "\n") // Correct splitting on new lines
	for _, word := range words {
		word = strings.TrimSpace(word) // Remove any leading/trailing whitespace
		if len(word) > 5 {             // Adjust the length condition as needed
			acceptableWords = append(acceptableWords, word)
		}
	}
	if len(acceptableWords) == 0 {
		return errors.New("no words imported into memory")
	}
	return nil
}

func randomInt(max int) int {
	b := make([]byte, 1)
	rand.Read(b)
	return int(b[0]) % max
}

func calculateEntropy(password string) float64 {
	length := len(password)
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
	var value float64
	if entropy == "avg" {
		value = 0.0
	} else {
		_, err := fmt.Sscanf(entropy, "%f", &value)
		if err != nil {
			log.Fatalf("Invalid entropy value: %s\n", entropy)
		}
	}
	return value
}

// intparts splits the integer i into parts of size p
func intparts(i, p int) []int {
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
	var totalEntropy, minEntropy, maxEntropy float64
	minEntropy = math.MaxFloat64
	var mu sync.Mutex

	coresToUse := cores
	if coresToUse == -1 {
		coresToUse = runtime.GOMAXPROCS(0)
	}

	chunks := intparts(count, count/coresToUse)
	startTime := time.Now()
	done := make(chan bool)

	go func() {
		for range time.Tick(1 * time.Second) {
			if time.Since(startTime) > 11*time.Second {
				go showSpinner(startTime, done)
				return
			}
		}
	}()

	var wg sync.WaitGroup

	for _, chunk := range chunks {
		chunk := chunk
		wg.Add(1)
		go func(chunk int) {
			defer wg.Done()
			var localTotalEntropy, localMinEntropy, localMaxEntropy float64
			localMinEntropy = math.MaxFloat64
			for i := 0; i < chunk; i++ {
				var password string
				if useWords {
					var wordErr error
					password, wordErr = generateWordPassword(length)
					if wordErr != nil {
						log.Printf("wordErr(%d) = %v", i, wordErr)
						continue
					}
				} else {
					password = generateRandomPassword(length)
				}

				entropy := calculateEntropy(password)
				localTotalEntropy += entropy
				if entropy < localMinEntropy {
					localMinEntropy = entropy
				}
				if entropy > localMaxEntropy {
					localMaxEntropy = entropy
				}
			}
			mu.Lock()
			totalEntropy += localTotalEntropy
			if localMinEntropy < minEntropy {
				minEntropy = localMinEntropy
			}
			if localMaxEntropy > maxEntropy {
				maxEntropy = localMaxEntropy
			}
			mu.Unlock()
		}(chunk)
		wg.Wait()
	}

	done <- true
	clearLine()

	avgEntropy := totalEntropy / float64(count)
	recommendedEntropy := (avgEntropy + maxEntropy) / 2 // > 75% of max
	return avgEntropy, minEntropy, maxEntropy, recommendedEntropy
}

// Define a custom writer that wraps an io.Writer
type cleanWriter struct {
	writer io.Writer
}

func (cw *cleanWriter) Write(p []byte) (n int, err error) {
	input := string(p)
	cleanedOutput := cleanOutput(input)
	return cw.writer.Write([]byte(cleanedOutput))
}

func cleanOutput(input string) string {
	cleaned := strings.SplitN(input, "[2K", 2)
	if len(cleaned) > 1 {
		return cleaned[1]
	}
	return input
}

func clearLine() {
	fmt.Printf("\r\033[2K") // Clear the line
}

func showSpinner(startTime time.Time, done chan bool) {
	spinner := []string{"|", "/", "-", "\\"}
	spinnerIndex := 0
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			clearLine()
			return
		case <-ticker.C:
			elapsed := time.Since(startTime).Seconds()
			fmt.Printf("\r\033[1;34mCalculating ... %.1fs %s\033[0m", elapsed, spinner[spinnerIndex])
			spinnerIndex = (spinnerIndex + 1) % len(spinner)
		}
	}
}
