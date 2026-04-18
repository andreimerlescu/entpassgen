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
// helpers
// ============================================================

// resetGlobals restores all package-level flags to their default
// values. Call defer resetGlobals() at the top of any test that
// mutates global state so subsequent tests start clean.
func resetGlobals() {
	skipUppercase = false
	skipLowercase = false
	skipSymbols = false
	skipDigits = false
	symbols = acceptableSymbols
	excludeSymbols = ""
	wordSeparators = acceptableWordSeparators
	useWords = false
	showJSON = false
	minEntropy = "avg"
	length = 17
	cores = -1
	quantity = 1
	acceptableWords = nil
}

// ============================================================
// randomInt
// ============================================================

func TestRandomInt_InRange(t *testing.T) {
	for i := 0; i < 10_000; i++ {
		v := randomInt(10)
		if v < 0 || v >= 10 {
			t.Fatalf("randomInt(10) = %d, want [0,10)", v)
		}
	}
}

func TestRandomInt_MaxOne(t *testing.T) {
	for i := 0; i < 1_000; i++ {
		v := randomInt(1)
		if v != 0 {
			t.Fatalf("randomInt(1) = %d, want 0", v)
		}
	}
}

func TestRandomInt_Distribution(t *testing.T) {
	// After the math/big fix, distribution across buckets must be
	// statistically uniform. Tolerance: ±10% of expected frequency.
	const max = 16
	const samples = 200_000
	counts := make([]int, max)
	for i := 0; i < samples; i++ {
		counts[randomInt(max)]++
	}
	expected := float64(samples) / float64(max)
	tolerance := expected * 0.10
	for i, c := range counts {
		if diff := math.Abs(float64(c) - expected); diff > tolerance {
			t.Errorf("bucket %d: got %d, expected ~%.0f (±%.0f)", i, c, expected, tolerance)
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
		t.Fatalf("expected 4 parts, got %d: %v", len(parts), parts)
	}
	for _, p := range parts {
		if p != 25 {
			t.Errorf("expected all parts = 25, got %d", p)
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
		t.Errorf("parts sum = %d, want 10; parts = %v", sum, parts)
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

// Guard added in Copilot review: p<=0 must not infinite-loop.
func TestIntparts_ZeroPartSize(t *testing.T) {
	parts := intparts(10, 0)
	if len(parts) != 1 || parts[0] != 10 {
		t.Errorf("intparts(10, 0) = %v, want [10]", parts)
	}
}

func TestIntparts_NegativePartSize(t *testing.T) {
	parts := intparts(10, -5)
	if len(parts) != 1 || parts[0] != 10 {
		t.Errorf("intparts(10, -5) = %v, want [10]", parts)
	}
}

func TestIntparts_SumAlwaysEqualsI(t *testing.T) {
	cases := [][2]int{
		{1, 1}, {7, 3}, {100, 7}, {99, 10}, {1000, 33},
	}
	for _, tc := range cases {
		parts := intparts(tc[0], tc[1])
		sum := 0
		for _, p := range parts {
			sum += p
		}
		if sum != tc[0] {
			t.Errorf("intparts(%d,%d) sum = %d, want %d", tc[0], tc[1], sum, tc[0])
		}
	}
}

// ============================================================
// calculateEntropy
// ============================================================

func TestCalculateEntropy_Empty(t *testing.T) {
	if e := calculateEntropy(""); e != 0 {
		t.Errorf("expected 0 for empty string, got %f", e)
	}
}

func TestCalculateEntropy_UniformString(t *testing.T) {
	if e := calculateEntropy("aaaaaaaaaa"); e != 0 {
		t.Errorf("expected 0 for uniform string, got %f", e)
	}
}

func TestCalculateEntropy_PositiveForDiverseInput(t *testing.T) {
	if e := calculateEntropy("aB3!xQ9#mZ2@kL5^"); e <= 0 {
		t.Errorf("expected positive entropy, got %f", e)
	}
}

func TestCalculateEntropy_LongerDiverseIsHigher(t *testing.T) {
	short := calculateEntropy("aB3!")
	long := calculateEntropy("aB3!xQ9#mZ2@kL5^nP7$")
	if long <= short {
		t.Errorf("longer diverse password should have higher entropy: short=%f long=%f", short, long)
	}
}

func TestCalculateEntropy_NeverNegative(t *testing.T) {
	cases := []string{
		"a", "aa", "abc", "aB3!xQ9#",
		strings.Repeat("a", 50),
		"!@#$%^&*()",
	}
	for _, tc := range cases {
		if e := calculateEntropy(tc); e < 0 {
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
		{"66.534", 66.534},
	}
	for _, tc := range cases {
		got := parseEntropy(tc.input)
		if math.Abs(got-tc.expected) > 1e-9 {
			t.Errorf("parseEntropy(%q) = %f, want %f", tc.input, got, tc.expected)
		}
	}
}

func TestParseEntropy_AvgReturnsZero(t *testing.T) {
	if got := parseEntropy("avg"); got != 0.0 {
		t.Errorf("parseEntropy(\"avg\") = %f, want 0.0", got)
	}
}

func TestParseEntropy_NegativeValue(t *testing.T) {
	// Negative entropy thresholds are technically parseable floats.
	// parseEntropy accepts them — all passwords will pass a negative threshold.
	got := parseEntropy("-1.0")
	if got != -1.0 {
		t.Errorf("parseEntropy(\"-1.0\") = %f, want -1.0", got)
	}
}

func FuzzParseEntropy(f *testing.F) {
	f.Add("avg")
	f.Add("9.32")
	f.Add("0.0")
	f.Add("100")
	f.Add("-1.0")
	f.Fuzz(func(t *testing.T, input string) {
		// Only exercise paths that do not call log.Fatalf.
		// log.Fatalf exits the process — uncatchable in fuzz targets.
		if input == "avg" {
			got := parseEntropy(input)
			if got != 0.0 {
				t.Errorf("parseEntropy(\"avg\") = %f, want 0.0", got)
			}
			return
		}
		var v float64
		if _, err := fmt.Sscanf(input, "%f", &v); err != nil {
			return // would fatal — skip
		}
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return // would fatal — skip
		}
		got := parseEntropy(input)
		if math.IsNaN(got) || math.IsInf(got, 0) {
			t.Errorf("parseEntropy(%q) returned NaN or Inf", input)
		}
	})
}

// ============================================================
// Entropy.Parse / Password.ParseEntropy
// ============================================================

func TestEntropyParse_AvgSetsMinEntropy(t *testing.T) {
	defer resetGlobals()
	minEntropy = "avg"
	p := Password{
		Sample:  &Sample{Average: 55.5, Max: 69.0},
		Entropy: Entropy{},
	}
	p.ParseEntropy()
	if minEntropy == "avg" {
		t.Error("minEntropy should have been resolved from avg to a numeric string")
	}
	// Resolved value should parse as the average
	got := parseEntropy(minEntropy)
	if math.Abs(got-55.5) > 0.001 {
		t.Errorf("resolved minEntropy = %f, want ~55.5", got)
	}
}

func TestEntropyParse_NumericPassthrough(t *testing.T) {
	defer resetGlobals()
	minEntropy = "50.0"
	p := Password{
		Sample:  &Sample{Average: 55.5, Max: 69.0},
		Entropy: Entropy{},
	}
	p.ParseEntropy()
	if minEntropy != "50.0" {
		t.Errorf("minEntropy should remain 50.0, got %s", minEntropy)
	}
}

func TestEntropyParse_ShorthandN(t *testing.T) {
	defer resetGlobals()
	// "n8" → "98.0"
	minEntropy = "n8"
	p := Password{Sample: &Sample{Average: 55.0, Max: 69.0}, Entropy: Entropy{}}
	p.ParseEntropy()
	got := parseEntropy(minEntropy)
	if math.Abs(got-98.0) > 1e-9 {
		t.Errorf("shorthand n8 → expected 98.0, got %f (minEntropy=%s)", got, minEntropy)
	}
}

func TestEntropyParse_ShorthandE(t *testing.T) {
	defer resetGlobals()
	// "e3" → "83.0"
	minEntropy = "e3"
	p := Password{Sample: &Sample{Average: 55.0, Max: 69.0}, Entropy: Entropy{}}
	p.ParseEntropy()
	got := parseEntropy(minEntropy)
	if math.Abs(got-83.0) > 1e-9 {
		t.Errorf("shorthand e3 → expected 83.0, got %f (minEntropy=%s)", got, minEntropy)
	}
}

func TestEntropyParse_ShorthandS(t *testing.T) {
	defer resetGlobals()
	// "s5" → "75.0"
	minEntropy = "s5"
	p := Password{Sample: &Sample{Average: 55.0, Max: 69.0}, Entropy: Entropy{}}
	p.ParseEntropy()
	got := parseEntropy(minEntropy)
	if math.Abs(got-75.0) > 1e-9 {
		t.Errorf("shorthand s5 → expected 75.0, got %f (minEntropy=%s)", got, minEntropy)
	}
}

// ============================================================
// generateRandomPassword
// ============================================================

func TestGenerateRandomPassword_Length(t *testing.T) {
	defer resetGlobals()
	for _, l := range []int{3, 8, 12, 17, 32, 64} {
		pw := generateRandomPassword(l)
		if len(pw) != l {
			t.Errorf("length %d: got password of length %d", l, len(pw))
		}
	}
}

func TestGenerateRandomPassword_AllCharClasses(t *testing.T) {
	defer resetGlobals()
	found := struct{ upper, lower, digit, symbol bool }{}
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
	t.Errorf("after 200 attempts not all char classes found: %+v", found)
}

func TestGenerateRandomPassword_SkipUppercase(t *testing.T) {
	defer resetGlobals()
	skipUppercase = true
	for i := 0; i < 500; i++ {
		pw := generateRandomPassword(20)
		for _, c := range pw {
			if unicode.IsUpper(c) {
				t.Fatalf("found uppercase in password with skipUppercase=true: %s", pw)
			}
		}
	}
}

func TestGenerateRandomPassword_SkipLowercase(t *testing.T) {
	defer resetGlobals()
	skipLowercase = true
	for i := 0; i < 500; i++ {
		pw := generateRandomPassword(20)
		for _, c := range pw {
			if unicode.IsLower(c) {
				t.Fatalf("found lowercase with skipLowercase=true: %s", pw)
			}
		}
	}
}

func TestGenerateRandomPassword_SkipDigits(t *testing.T) {
	defer resetGlobals()
	skipDigits = true
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
	defer resetGlobals()
	skipSymbols = true
	valid := acceptableUppercase + acceptableLowercase + acceptableDigits
	for i := 0; i < 500; i++ {
		pw := generateRandomPassword(20)
		for _, c := range pw {
			if !strings.ContainsRune(valid, c) {
				t.Fatalf("found symbol with skipSymbols=true: %s", pw)
			}
		}
	}
}

func TestGenerateRandomPassword_ExcludeSymbols(t *testing.T) {
	defer resetGlobals()
	excludeSymbols = "!@#"
	for i := 0; i < 500; i++ {
		if pw := generateRandomPassword(30); strings.ContainsAny(pw, "!@#") {
			t.Fatalf("found excluded symbol in: %s", pw)
		}
	}
}

func TestGenerateRandomPassword_CustomSymbols(t *testing.T) {
	defer resetGlobals()
	skipUppercase = true
	skipLowercase = true
	skipDigits = true
	symbols = "abc"
	for i := 0; i < 200; i++ {
		pw := generateRandomPassword(20)
		for _, c := range pw {
			if !strings.ContainsRune("abc", c) {
				t.Fatalf("found char outside custom symbol set in: %s", pw)
			}
		}
	}
}

func FuzzGenerateRandomPassword(f *testing.F) {
	f.Add(3)
	f.Add(12)
	f.Add(17)
	f.Add(64)
	f.Fuzz(func(t *testing.T, l int) {
		if l < 3 || l > 10_000 {
			return
		}
		resetGlobals()
		pw := generateRandomPassword(l)
		if len(pw) != l {
			t.Errorf("generateRandomPassword(%d) returned length %d", l, len(pw))
		}
	})
}

func BenchmarkGenerateRandomPassword_Short(b *testing.B) {
	b.Cleanup(resetGlobals)
	for i := 0; i < b.N; i++ {
		generateRandomPassword(12)
	}
}

func BenchmarkGenerateRandomPassword_Long(b *testing.B) {
	b.Cleanup(resetGlobals)
	for i := 0; i < b.N; i++ {
		generateRandomPassword(64)
	}
}

// ============================================================
// loadWords + generateWordPassword
// ============================================================

func TestLoadWords_LoadsWords(t *testing.T) {
	defer resetGlobals()
	err := loadWords()
	if err != nil {
		t.Fatalf("loadWords() error: %v", err)
	}
	if len(acceptableWords) < 50 {
		t.Errorf("expected ≥50 words, got %d", len(acceptableWords))
	}
}

func TestLoadWords_Idempotent(t *testing.T) {
	defer resetGlobals()
	_ = loadWords()
	count := len(acceptableWords)
	_ = loadWords()
	if len(acceptableWords) != count {
		t.Errorf("loadWords() not idempotent: first=%d second=%d", count, len(acceptableWords))
	}
}

func TestLoadWords_MinWordLength(t *testing.T) {
	defer resetGlobals()
	_ = loadWords()
	for _, w := range acceptableWords {
		if len(w) <= 5 {
			t.Errorf("word %q is too short (must be >5 chars)", w)
		}
	}
}

func TestGenerateWordPassword_ReturnsNonEmpty(t *testing.T) {
	defer resetGlobals()
	for _, count := range []int{1, 3, 5, 10} {
		pw, err := generateWordPassword(count)
		if err != nil {
			t.Fatalf("generateWordPassword(%d) error: %v", count, err)
		}
		if strings.TrimSpace(pw) == "" {
			t.Errorf("generateWordPassword(%d) returned empty string", count)
		}
	}
}

func TestGenerateWordPassword_RespectsWordSeparators(t *testing.T) {
	defer resetGlobals()
	// Restrict separators to a single known character so we can assert on it.
	wordSeparators = "-"
	pw, err := generateWordPassword(3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// A 3-word password should contain exactly 2 separators.
	count := strings.Count(pw, "-")
	if count != 2 {
		t.Errorf("expected 2 '-' separators in %q, got %d", pw, count)
	}
}

func TestGenerateWordPassword_EmptySepsAfterExclusion(t *testing.T) {
	defer resetGlobals()
	// Set seps to a single char then exclude it — must return an error,
	// not pass 0 to randomInt.
	wordSeparators = "!"
	excludeSymbols = "!"
	_, err := generateWordPassword(3)
	if err == nil {
		t.Error("expected error when separator set is empty after exclusion, got nil")
	}
}

func TestGenerateWordPassword_ExcludeSymbolsHonoured(t *testing.T) {
	defer resetGlobals()
	excludeSymbols = "!"
	for i := 0; i < 200; i++ {
		pw, err := generateWordPassword(3)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.Contains(pw, "!") {
			t.Fatalf("found excluded separator '!' in: %s", pw)
		}
	}
}

func BenchmarkGenerateWordPassword(b *testing.B) {
	b.Cleanup(resetGlobals)
	_ = loadWords()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = generateWordPassword(5)
	}
}

// ============================================================
// calculateAverageEntropy
// ============================================================

func TestCalculateAverageEntropy_Invariants(t *testing.T) {
	defer resetGlobals()
	cores = 2
	avg, min, max, recommended := calculateAverageEntropy(500)

	if avg <= 0 {
		t.Errorf("avg should be positive, got %f", avg)
	}
	if min <= 0 {
		t.Errorf("min should be positive, got %f", min)
	}
	if max < avg {
		t.Errorf("max (%f) should be ≥ avg (%f)", max, avg)
	}
	if min > avg {
		t.Errorf("min (%f) should be ≤ avg (%f)", min, avg)
	}
	if recommended < avg {
		t.Errorf("recommended (%f) should be ≥ avg (%f)", recommended, avg)
	}
	if recommended > max {
		t.Errorf("recommended (%f) should be ≤ max (%f)", recommended, max)
	}
}

func BenchmarkCalculateAverageEntropy(b *testing.B) {
	b.Cleanup(resetGlobals)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		calculateAverageEntropy(1000)
	}
}

// ============================================================
// PrintJSON / AsJSON
// ============================================================

func TestPrintJSON_WritesValidJSON(t *testing.T) {
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
		t.Errorf("round-trip value: got %q want %q", out.Value, p.Value)
	}
}

func TestAsJSON_WritesValidJSON(t *testing.T) {
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
	var out Password
	if err := json.Unmarshal([]byte(AsJSON(original)), &out); err != nil {
		t.Fatalf("round-trip unmarshal failed: %v", err)
	}
	if out.Value != original.Value {
		t.Errorf("value: got %q want %q", out.Value, original.Value)
	}
	if math.Abs(out.Entropy.Score-original.Entropy.Score) > 1e-9 {
		t.Errorf("entropy score: got %f want %f", out.Entropy.Score, original.Entropy.Score)
	}
	if out.Sample.Average != original.Sample.Average {
		t.Errorf("sample average: got %f want %f", out.Sample.Average, original.Sample.Average)
	}
}

// ============================================================
// DeliverResults
// ============================================================

func TestDeliverResults_SinglePassword_Text(t *testing.T) {
	defer resetGlobals()
	showJSON = false

	store := NewPasswordStore()
	store.Add(Password{Value: "SingleResult1!"})

	var buf bytes.Buffer
	DeliverResults(store, &buf)

	got := buf.String()
	if got != "SingleResult1!" {
		t.Errorf("DeliverResults single text: got %q, want %q", got, "SingleResult1!")
	}
}

func TestDeliverResults_MultiplePasswords_Text(t *testing.T) {
	defer resetGlobals()
	showJSON = false

	store := NewPasswordStore()
	store.Add(Password{Value: "alpha1!"})
	store.Add(Password{Value: "bravo2@"})
	store.Add(Password{Value: "charlie3#"})

	var buf bytes.Buffer
	DeliverResults(store, &buf)

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 lines, got %d: %v", len(lines), lines)
	}
}

func TestDeliverResults_SinglePassword_JSON(t *testing.T) {
	defer resetGlobals()
	showJSON = true

	store := NewPasswordStore()
	store.Add(Password{Value: "JsonResult1!", Length: 12})

	var buf bytes.Buffer
	DeliverResults(store, &buf)

	var out Password
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("single JSON output is not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if out.Value != "JsonResult1!" {
		t.Errorf("JSON value: got %q want %q", out.Value, "JsonResult1!")
	}
}

func TestDeliverResults_MultiplePasswords_JSON(t *testing.T) {
	defer resetGlobals()
	showJSON = true

	store := NewPasswordStore()
	store.Add(Password{Value: "first1!"})
	store.Add(Password{Value: "second2@"})

	var buf bytes.Buffer
	DeliverResults(store, &buf)

	var out []Password
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("multi JSON output is not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if len(out) != 2 {
		t.Errorf("expected 2 passwords in JSON array, got %d", len(out))
	}
}

func TestDeliverResults_PreservesInsertionOrder(t *testing.T) {
	defer resetGlobals()
	showJSON = false

	store := NewPasswordStore()
	expected := []string{"first1!", "second2@", "third3#"}
	for _, v := range expected {
		store.Add(Password{Value: v})
	}

	var buf bytes.Buffer
	DeliverResults(store, &buf)

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	for i, line := range lines {
		if line != expected[i] {
			t.Errorf("line %d: got %q, want %q", i, line, expected[i])
		}
	}
}

// ============================================================
// PasswordStore
// ============================================================

func TestPasswordStore_DeduplicatesSilently(t *testing.T) {
	store := NewPasswordStore()
	first := store.Add(Password{Value: "duplicate!"})
	second := store.Add(Password{Value: "duplicate!"})
	if !first {
		t.Error("first Add should return true")
	}
	if second {
		t.Error("second Add of same value should return false")
	}
	if store.Len() != 1 {
		t.Errorf("store.Len() = %d, want 1", store.Len())
	}
}

func TestPasswordStore_LenMatchesUniqueAdds(t *testing.T) {
	store := NewPasswordStore()
	for i := 0; i < 10; i++ {
		store.Add(Password{Value: fmt.Sprintf("pw%d!", i)})
	}
	if store.Len() != 10 {
		t.Errorf("store.Len() = %d, want 10", store.Len())
	}
}

func TestPasswordStore_ItemsReturnsCopy(t *testing.T) {
	store := NewPasswordStore()
	store.Add(Password{Value: "immutable!"})
	items := store.Items()
	items[0].Value = "mutated"
	// Internal state must not be affected
	if store.Items()[0].Value == "mutated" {
		t.Error("Items() returned a reference to internal slice, not a copy")
	}
}

func TestPasswordStore_PreservesOrder(t *testing.T) {
	store := NewPasswordStore()
	vals := []string{"a1!", "b2@", "c3#", "d4$", "e5%"}
	for _, v := range vals {
		store.Add(Password{Value: v})
	}
	for i, p := range store.Items() {
		if p.Value != vals[i] {
			t.Errorf("position %d: got %q, want %q", i, p.Value, vals[i])
		}
	}
}
