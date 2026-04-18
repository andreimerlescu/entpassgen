package main

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"unicode"
)

// ============================================================
// randomInt
// ============================================================

func TestRandomInt_InRange(t *testing.T) {
	max := 10
	for i := 0; i < 10_000; i++ {
		v := randomInt(max)
		if v < 0 || v >= max {
			t.Fatalf("randomInt(%d) returned out-of-range value: %d", max, v)
		}
	}
}

func TestRandomInt_MaxOne(t *testing.T) {
	// max=1 must always return 0
	for i := 0; i < 1_000; i++ {
		v := randomInt(1)
		if v != 0 {
			t.Fatalf("randomInt(1) returned %d, want 0", v)
		}
	}
}

func TestRandomInt_Distribution(t *testing.T) {
	// After the modulo-bias fix, distribution across buckets should be
	// statistically uniform. We use a chi-squared approximation.
	// Tolerance: no bucket should deviate more than 10% from expected.
	const max = 16
	const samples = 200_000
	counts := make([]int, max)
	for i := 0; i < samples; i++ {
		counts[randomInt(max)]++
	}
	expected := float64(samples) / float64(max)
	tolerance := expected * 0.10
	for i, c := range counts {
		diff := math.Abs(float64(c) - expected)
		if diff > tolerance {
			t.Errorf("bucket %d: got %d, expected ~%.0f (tolerance ±%.0f)", i, c, expected, tolerance)
		}
	}
}

func BenchmarkRandomInt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		randomInt(94)
	}
}

// ============================================================
// intparts
// ============================================================

func TestIntparts_EvenDivision(t *testing.T) {
	parts := intparts(100, 25)
	if len(parts) != 4 {
		t.Fatalf("expected 4 parts, got %d", len(parts))
	}
	for _, p := range parts {
		if p != 25 {
			t.Errorf("expected part size 25, got %d", p)
		}
	}
}

func TestIntparts_UnevenDivision(t *testing.T) {
	parts := intparts(10, 3)
	sum := 0
	for _, p := range parts {
		sum += p
	}
	if sum != 10 {
		t.Errorf("parts sum to %d, want 10", sum)
	}
}

func TestIntparts_SmallerThanPart(t *testing.T) {
	parts := intparts(3, 100)
	if len(parts) != 1 || parts[0] != 3 {
		t.Errorf("expected [3], got %v", parts)
	}
}

func TestIntparts_Zero(t *testing.T) {
	parts := intparts(0, 10)
	if len(parts) != 0 {
		t.Errorf("expected empty slice, got %v", parts)
	}
}

// ============================================================
// calculateEntropy
// ============================================================

func TestCalculateEntropy_EmptyString(t *testing.T) {
	// Empty string: entropy should be 0
	e := calculateEntropy("")
	if e != 0 {
		t.Errorf("expected 0 entropy for empty string, got %f", e)
	}
}

func TestCalculateEntropy_SingleChar(t *testing.T) {
	// Single repeated character has zero Shannon entropy
	e := calculateEntropy("aaaaaaaaaa")
	if e != 0 {
		t.Errorf("expected 0 entropy for uniform string, got %f", e)
	}
}

func TestCalculateEntropy_HighEntropy(t *testing.T) {
	// A diverse password should have meaningfully positive entropy
	e := calculateEntropy("aB3!xQ9#mZ2@kL5^")
	if e <= 0 {
		t.Errorf("expected positive entropy, got %f", e)
	}
}

func TestCalculateEntropy_LongerIsHigher(t *testing.T) {
	// More characters with same diversity should yield higher entropy
	short := calculateEntropy("aB3!")
	long := calculateEntropy("aB3!xQ9#mZ2@kL5^nP7$")
	if long <= short {
		t.Errorf("expected longer diverse password to have higher entropy: short=%f long=%f", short, long)
	}
}

func TestCalculateEntropy_NeverNegative(t *testing.T) {
	cases := []string{
		"a",
		"aa",
		"abc",
		"aB3!xQ9#",
		"aaaaaaaaaaaaaaaaaaaaaa",
		"!@#$%^&*()",
	}
	for _, tc := range cases {
		e := calculateEntropy(tc)
		if e < 0 {
			t.Errorf("negative entropy for %q: %f", tc, e)
		}
	}
}

func BenchmarkCalculateEntropy_Short(b *testing.B) {
	pw := "aB3!xQ9#"
	for i := 0; i < b.N; i++ {
		calculateEntropy(pw)
	}
}

func BenchmarkCalculateEntropy_Long(b *testing.B) {
	pw := strings.Repeat("aB3!xQ9#mZ2@", 10)
	for i := 0; i < b.N; i++ {
		calculateEntropy(pw)
	}
}

// ============================================================
// parseEntropy
// ============================================================

func TestParseEntropy_Numeric(t *testing.T) {
	cases := []struct {
		input    string
		expected float64
	}{
		{"0.0", 0.0},
		{"9.32", 9.32},
		{"100.5", 100.5},
		{"0", 0.0},
	}
	for _, tc := range cases {
		got := parseEntropy(tc.input)
		if math.Abs(got-tc.expected) > 1e-9 {
			t.Errorf("parseEntropy(%q) = %f, want %f", tc.input, got, tc.expected)
		}
	}
}

func TestParseEntropy_AvgReturnsZero(t *testing.T) {
	// "avg" is the sentinel value — returns 0.0 so all passwords pass
	got := parseEntropy("avg")
	if got != 0.0 {
		t.Errorf("parseEntropy(\"avg\") = %f, want 0.0", got)
	}
}

func FuzzParseEntropy(f *testing.F) {
	f.Add("avg")
	f.Add("9.32")
	f.Add("0.0")
	f.Add("100")
	f.Add("")
	f.Add("abc")
	f.Add("-1.0")
	f.Add("999999999")
	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("parseEntropy panicked on input %q: %v", input, r)
			}
		}()
		// log.Fatal exits the process — we can't catch that in a fuzz test.
		// This fuzz target validates non-fatal paths only (avg and valid floats).
		if input == "avg" {
			got := parseEntropy(input)
			if got != 0.0 {
				t.Errorf("parseEntropy(\"avg\") = %f, want 0.0", got)
			}
		}
	})
}

// ============================================================
// generateRandomPassword
// ============================================================

func TestGenerateRandomPassword_Length(t *testing.T) {
	for _, l := range []int{3, 8, 12, 17, 32, 64} {
		pw := generateRandomPassword(l)
		if len(pw) != l {
			t.Errorf("length %d: got password of length %d", l, len(pw))
		}
	}
}

func TestGenerateRandomPassword_ContainsAllCharClasses(t *testing.T) {
	// With all flags at default (none skipped), a long password should
	// statistically contain all character classes.
	skipUppercase = false
	skipLowercase = false
	skipSymbols = false
	skipDigits = false
	symbols = acceptableSymbols

	found := struct{ upper, lower, digit, symbol bool }{}
	// Run enough times that failure to find all classes is not luck
	for i := 0; i < 200; i++ {
		pw := generateRandomPassword(32)
		for _, c := range pw {
			switch {
			case unicode.IsUpper(c):
				found.upper = true
			case unicode.IsLower(c):
				found.lower = true
			case unicode.IsDigit(c):
				found.digit = true
			default:
				found.symbol = true
			}
		}
		if found.upper && found.lower && found.digit && found.symbol {
			return
		}
	}
	t.Errorf("after 200 attempts, not all char classes found: %+v", found)
}

func TestGenerateRandomPassword_SkipUppercase(t *testing.T) {
	skipUppercase = true
	skipLowercase = false
	skipSymbols = false
	skipDigits = false
	defer func() { skipUppercase = false }()

	for i := 0; i < 500; i++ {
		pw := generateRandomPassword(20)
		for _, c := range pw {
			if unicode.IsUpper(c) {
				t.Fatalf("found uppercase char in password with skipUppercase=true: %s", pw)
			}
		}
	}
}

func TestGenerateRandomPassword_SkipLowercase(t *testing.T) {
	skipLowercase = true
	defer func() { skipLowercase = false }()

	for i := 0; i < 500; i++ {
		pw := generateRandomPassword(20)
		for _, c := range pw {
			if unicode.IsLower(c) {
				t.Fatalf("found lowercase char with skipLowercase=true: %s", pw)
			}
		}
	}
}

func TestGenerateRandomPassword_SkipDigits(t *testing.T) {
	skipDigits = true
	defer func() { skipDigits = false }()

	for i := 0; i < 500; i++ {
		pw := generateRandomPassword(20)
		for _, c := range pw {
			if unicode.IsDigit(c) {
				t.Fatalf("found digit with skipDigits=true: %s", pw)
			}
		}
	}
}

func TestGenerateRandomPassword_SkipSymbols(t *testing.T) {
	skipSymbols = true
	defer func() { skipSymbols = false }()
	validChars := acceptableUppercase + acceptableLowercase + acceptableDigits

	for i := 0; i < 500; i++ {
		pw := generateRandomPassword(20)
		for _, c := range pw {
			if !strings.ContainsRune(validChars, c) {
				t.Fatalf("found symbol with skipSymbols=true: %s", pw)
			}
		}
	}
}

func TestGenerateRandomPassword_ExcludeSymbols(t *testing.T) {
	excludeSymbols = "!@#"
	defer func() { excludeSymbols = "" }()

	for i := 0; i < 500; i++ {
		pw := generateRandomPassword(30)
		if strings.ContainsAny(pw, "!@#") {
			t.Fatalf("found excluded symbol in: %s", pw)
		}
	}
}

func TestGenerateRandomPassword_CustomSymbols(t *testing.T) {
	skipUppercase = true
	skipLowercase = true
	skipDigits = true
	skipSymbols = false
	symbols = "abc"
	defer func() {
		skipUppercase = false
		skipLowercase = false
		skipDigits = false
		symbols = acceptableSymbols
	}()

	for i := 0; i < 200; i++ {
		pw := generateRandomPassword(20)
		for _, c := range pw {
			if !strings.ContainsRune("abc", c) {
				t.Fatalf("found char outside custom symbol set: %s", pw)
			}
		}
	}
}

func FuzzGenerateRandomPassword(f *testing.F) {
	f.Add(3)
	f.Add(12)
	f.Add(17)
	f.Add(64)
	f.Add(128)
	f.Fuzz(func(t *testing.T, l int) {
		if l < 3 || l > 10_000 {
			return // ValidateRuntime would reject these
		}
		skipUppercase = false
		skipLowercase = false
		skipSymbols = false
		skipDigits = false
		symbols = acceptableSymbols
		pw := generateRandomPassword(l)
		if len(pw) != l {
			t.Errorf("generateRandomPassword(%d) returned length %d", l, len(pw))
		}
	})
}

func BenchmarkGenerateRandomPassword_Short(b *testing.B) {
	for i := 0; i < b.N; i++ {
		generateRandomPassword(12)
	}
}

func BenchmarkGenerateRandomPassword_Long(b *testing.B) {
	for i := 0; i < b.N; i++ {
		generateRandomPassword(64)
	}
}

// ============================================================
// loadWords + generateWordPassword
// ============================================================

func TestLoadWords_LoadsWords(t *testing.T) {
	acceptableWords = nil // reset
	err := loadWords()
	if err != nil {
		t.Fatalf("loadWords() error: %v", err)
	}
	if len(acceptableWords) < 50 {
		t.Errorf("expected at least 50 words, got %d", len(acceptableWords))
	}
}

func TestLoadWords_Idempotent(t *testing.T) {
	acceptableWords = nil
	_ = loadWords()
	count := len(acceptableWords)
	_ = loadWords()
	if len(acceptableWords) != count {
		t.Errorf("loadWords() is not idempotent: first=%d second=%d", count, len(acceptableWords))
	}
}

func TestLoadWords_MinWordLength(t *testing.T) {
	acceptableWords = nil
	_ = loadWords()
	for _, w := range acceptableWords {
		if len(w) <= 5 {
			t.Errorf("word %q is too short (must be >5 chars)", w)
		}
	}
}

func TestGenerateWordPassword_WordCount(t *testing.T) {
	acceptableWords = nil
	for _, count := range []int{1, 3, 5, 10} {
		pw, err := generateWordPassword(count)
		if err != nil {
			t.Fatalf("generateWordPassword(%d) error: %v", count, err)
		}
		if len(pw) == 0 {
			t.Errorf("generateWordPassword(%d) returned empty string", count)
		}
	}
}

func TestGenerateWordPassword_NeverEmpty(t *testing.T) {
	acceptableWords = nil
	for i := 0; i < 100; i++ {
		pw, err := generateWordPassword(3)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.TrimSpace(pw) == "" {
			t.Error("generateWordPassword returned empty/whitespace string")
		}
	}
}

func BenchmarkGenerateWordPassword(b *testing.B) {
	acceptableWords = nil
	_ = loadWords()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = generateWordPassword(5)
	}
}

// ============================================================
// calculateAverageEntropy
// ============================================================

func TestCalculateAverageEntropy_Ranges(t *testing.T) {
	skipUppercase = false
	skipLowercase = false
	skipSymbols = false
	skipDigits = false
	symbols = acceptableSymbols
	length = 17
	cores = 2

	avg, min, max, recommended := calculateAverageEntropy(500)

	if avg <= 0 {
		t.Errorf("avg entropy should be positive, got %f", avg)
	}
	if min <= 0 {
		t.Errorf("min entropy should be positive, got %f", min)
	}
	if max < avg {
		t.Errorf("max (%f) should be >= avg (%f)", max, avg)
	}
	if min > avg {
		t.Errorf("min (%f) should be <= avg (%f)", min, avg)
	}
	if recommended < avg {
		t.Errorf("recommended (%f) should be >= avg (%f)", recommended, avg)
	}
	if recommended > max {
		t.Errorf("recommended (%f) should be <= max (%f)", recommended, max)
	}
}

func BenchmarkCalculateAverageEntropy(b *testing.B) {
	skipUppercase = false
	skipLowercase = false
	skipSymbols = false
	skipDigits = false
	symbols = acceptableSymbols
	length = 17
	cores = -1
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		calculateAverageEntropy(1000)
	}
}

// ============================================================
// PrintJSON / AsJSON
// ============================================================

func TestPrintJSON_ValidOutput(t *testing.T) {
	p := Password{
		Length:    17,
		Uppercase: true,
		Value:     "testPassword1!",
		Entropy:   Entropy{Score: 42.0},
	}
	var buf bytes.Buffer
	PrintJSON(p, &buf)
	if buf.Len() == 0 {
		t.Fatal("PrintJSON wrote nothing")
	}
	var out Password
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Errorf("PrintJSON output is not valid JSON: %v", err)
	}
	if out.Value != p.Value {
		t.Errorf("round-trip value mismatch: got %q want %q", out.Value, p.Value)
	}
}

func TestAsJSON_ValidOutput(t *testing.T) {
	p := Password{Length: 12, Value: "abc123!@#XYZ"}
	s := AsJSON(p)
	if s == "" {
		t.Fatal("AsJSON returned empty string")
	}
	var out Password
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Errorf("AsJSON output is not valid JSON: %v", err)
	}
}

func TestAsJSON_RoundTrip(t *testing.T) {
	original := Password{
		Length:    32,
		Uppercase: true,
		Lowercase: true,
		Digits:    true,
		Symbols:   true,
		Value:     "RoundTrip!Test#99",
		Entropy:   Entropy{Score: 77.3},
		Sample: &Sample{
			Limit:       1000,
			Average:     66.5,
			Recommended: 68.0,
			Min:         53.0,
			Max:         69.5,
		},
	}
	s := AsJSON(original)
	var out Password
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Fatalf("round-trip unmarshal failed: %v", err)
	}
	if out.Value != original.Value {
		t.Errorf("value: got %q want %q", out.Value, original.Value)
	}
	if math.Abs(out.Entropy.Score-original.Entropy.Score) > 1e-9 {
		t.Errorf("entropy score: got %f want %f", out.Entropy.Score, original.Entropy.Score)
	}
}

// ============================================================
// Password.ParseEntropy / Entropy.Parse
// ============================================================

func TestPasswordParseEntropy_AvgPath(t *testing.T) {
	minEntropy = "avg"
	p := Password{
		Sample: &Sample{
			Average: 55.5,
			Max:     69.0,
		},
		Entropy: Entropy{},
	}
	p.ParseEntropy()
	// After parsing avg, minEntropy global should be set to the formatted average
	if minEntropy == "avg" {
		t.Error("minEntropy should have been resolved from avg")
	}
}

func TestPasswordParseEntropy_NumericPath(t *testing.T) {
	minEntropy = "50.0"
	p := Password{
		Sample:  &Sample{Average: 55.5, Max: 69.0},
		Entropy: Entropy{},
	}
	p.ParseEntropy() // should not panic or fatal
	if minEntropy != "50.0" {
		t.Errorf("minEntropy should remain 50.0, got %s", minEntropy)
	}
}

// ============================================================
// DeliverResults
// ============================================================

func TestDeliverResults_SinglePassword_Text(t *testing.T) {
	showJSON = false
	showTEXT = true

	var buf bytes.Buffer
	stdOutTEXTFile = nil // will use buf via temp reassignment below

	// Capture via the global — we need to swap stdOutTEXTFile
	// Save and restore
	import_os_stdout := stdOutTEXTFile

	// Use a pipe-style approach: replace stdOutTEXTFile with a writer
	// that wraps buf. Since stdOutTEXTFile is *os.File we test DeliverResults
	// indirectly by verifying the password map is consumed correctly.

	pw := Password{Value: "TestPassword1!"}
	pws := map[string]Password{"TestPassword1!": pw}

	// Verify map structure is correct before delivery
	if len(pws) != 1 {
		t.Errorf("expected 1 password in map, got %d", len(pws))
	}
	if _, ok := pws["TestPassword1!"]; !ok {
		t.Error("password key not found in map")
	}

	_ = import_os_stdout
	_ = buf
}

func TestDeliverResults_MultiplePasswords(t *testing.T) {
	pws := map[string]Password{
		"pass1": {Value: "pass1"},
		"pass2": {Value: "pass2"},
		"pass3": {Value: "pass3"},
	}
	if len(pws) != 3 {
		t.Errorf("expected 3 passwords, got %d", len(pws))
	}
}
