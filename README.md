# Entropy (focused) Password Generator

![entpassgen Created by Andrei Merlescu](/entpassgen.jpg)

[![Go Report Card](https://goreportcard.com/badge/github.com/andreimerlescu/entpassgen)](https://goreportcard.com/report/github.com/andreimerlescu/entpassgen)
![GitHub Release](https://img.shields.io/github/v/release/andreimerlescu/entpassgen)
![GitHub License](https://img.shields.io/github/license/andreimerlescu/entpassgen)
![GitHub branch status](https://img.shields.io/github/checks-status/andreimerlescu/entpassgen/master)
![GitHub top language](https://img.shields.io/github/languages/top/andreimerlescu/entpassgen)

[Open/Source/Insights @entpassgen](https://deps.dev/go/github.com%2Fandreimerlescu%2Fentpassgen) · [Go Package @entpassgen](https://pkg.go.dev/github.com/andreimerlescu/entpassgen)

`entpassgen` is a pure-Go password generator built around entropy awareness. It uses `crypto/rand` for all randomness and supports both character-based and word-based generation. No third-party dependencies — only the standard library.

---

## What "entropy score" means

The `-e` flag and JSON `entropy.score` field report a **Shannon-derived score**: `−H(X)·L`, where `H(X)` is the per-character Shannon entropy and `L` is the password length. This measures **character-distribution uniformity** within the generated string.

It does **not** measure brute-force resistance. Search-space strength for a randomly generated password is `log₂(charsetSize^length)` — a fixed value that depends only on the charset size and length chosen, not on which specific characters appear.

The default `-e avg` is intentional and adaptive: it samples `-k` passwords under your exact current settings, computes the average Shannon score for that distribution, then uses that average as the acceptance floor. This means the threshold is always calibrated to what is actually achievable with your chosen length, charset, and character class flags — not a hardcoded value that may be unreachable or trivially easy for your configuration.

Use `-a` to see the full distribution (average, min, max, recommended) before generating.

---

## Getting Started

Requires **Go 1.22+**.

```zsh
# Install via Go
go install github.com/andreimerlescu/entpassgen@latest
entpassgen -h

# Clone, build and install to ~/bin
git clone git@github.com:andreimerlescu/entpassgen.git
cd entpassgen
make install

# Download a pre-built binary (Linux amd64)
curl -o ./entpassgen -s https://github.com/andreimerlescu/entpassgen/releases/download/v1.1.0/entpassgen.linux-amd64
chmod +x entpassgen
mv entpassgen ~/bin/entpassgen
entpassgen -h
```

### Windows

```powershell
# Install via Go
go install github.com/andreimerlescu/entpassgen@latest
entpassgen.exe -h

# Download pre-built binary (run as Administrator)
New-Item -ItemType Directory -Force -Path C:\bin
setx /M PATH "%PATH%;C:\bin"
Invoke-WebRequest "https://github.com/andreimerlescu/entpassgen/releases/download/v1.1.0/entpassgen.windows-amd64.exe" -OutFile C:\bin\entpassgen.exe
entpassgen.exe -h
```

---

## Flag Reference

    Usage of entpassgen:
      -E string
            Characters to exclude from the password
      -L    Do not use lowercase characters
      -N    Do not use digits
      -S    Do not use symbols
      -U    Do not use uppercase characters
      -W string
            Characters used to separate words in -w mode
            (default "!@#$%^&*()_+1234567890-=,.></?;:[]|")
      -a    Print an entropy analysis report for the current options (to stderr)
      -c int
            Goroutines for entropy sampling; -1 = GOMAXPROCS (default -1)
      -e string
            Minimum Shannon entropy score to accept.
            Special values:
              avg       compute average entropy from -k samples, use as floor (default)
              0         accept any password — no entropy filter
              n0–n9     shorthand for 90.0–99.0
              e0–e9     shorthand for 80.0–89.0
              s0–s9     shorthand for 70.0–79.0
            Note: if the floor exceeds what is achievable at your chosen -l and
            character class settings, the tool will exit with an error. Run -a
            first to see the achievable range.
      -j    JSON formatted output
      -k int
            Sample size for -a or -e avg (default 100000)
      -l int
            Password length: character count (-w=false) or word count (-w=true)
            (default: 17 chars, or 5 words with -w)
      -o string
            Write output to this file instead of stdout
      -q int
            Number of passwords to generate (default 1, max 434)
      -s string
            Acceptable symbol characters
            (default "!@#$%^&*()_+=-[]\\{}|;':,./<>?")
      -v    Print version and exit
      -w    Use words instead of characters (ignores -U -L -S -E -N -s)

---

## Examples

### One password (defaults)

    $ entpassgen
    v>s81|/7:UmrzKXE{

### One password, JSON output

    $ entpassgen -j | jq '.'
    {
      "length": 17,
      "uppercase": true,
      "lowercase": true,
      "digits": true,
      "symbols": true,
      "value": "v>s81|/7:UmrzKXE{",
      "sample": {
        "limit": 100000,
        "average": 66.541,
        "recommended": 68.014,
        "min": 49.487,
        "max": 69.487
      },
      "entropy": {
        "score": 69.487
      }
    }

### Ten passwords (defaults)

    $ entpassgen -q 10
    r<GcVng4W$iA@JQ#\
    x3Q^MT4q2Xmp,ly>G
    t!LH7uvnNT9aiQDD>
    ywEaYRpl\CWv;Jh52
    Ebfh1sHNao2HwM8>u
    ,XTG@vUx2V{y0:7TC
    ;4W^w]E:t|ZqJ*WnU
    X(og^y^*3nhRfq=7j
    OcZSm[#>I.WjU,o>5
    w:ng1H+jNtrL!2ETr

### Word-based password (3 words)

    $ entpassgen -w -l 3
    misserve(kinematographic]daunii

### No symbols — alphanumeric only

    $ entpassgen -S
    ZxZ8zOoKym8qDdk07

### Random 9-digit number

    $ entpassgen -L -U -S -l 9
    804799183

### Custom character set — Hebrew letters only

    $ entpassgen -L -U -N -S -s "אבגדהוזחטיכלמנסעפצקרשת" -l 12 -q 5
    גקגתתעשנפכט
    שבגדעהתלנמ
    כדעפמכלכחת
    כגטששתחטצת
    טכלננמנסא

### Entropy analysis report

The `-a` flag prints a report to **stderr** (keeping stdout clean for piping) then outputs the password as normal.

    $ entpassgen -a

    Entropy Report:
      Samples:     100000
      Length:      17
      Uppercase:   true
      Lowercase:   true
      Digits:      true
      Symbols:     true
      Use Words:   false
      Average:     66.534
      Minimum:     53.487
      Maximum:     69.487
      Recommended: 68.010

    v>s81|/7:UmrzKXE{

Word-based analysis:

    $ entpassgen -w -a

    Entropy Report:
      Samples:     100000
      Length:      5
      Uppercase:   true
      Lowercase:   true
      Digits:      true
      Symbols:     true
      Use Words:   true
      Average:     221.935
      Minimum:     141.402
      Maximum:     328.852
      Recommended: 275.393

    correct(horse_battery+staple!login

### Entropy floor and length interaction

The achievable Shannon score ceiling is bounded by password length. If your `-e` floor exceeds what is possible at your chosen `-l`, the tool exits with an error:

    $ entpassgen -l 21 -e n2    # n2 = 92.0 — within range, works
    $ entpassgen -l 21 -e n3    # n3 = 93.0 — above ceiling for length 21, fails

    2026/04/19 14:44:41 run: could not find a password meeting entropy threshold 93.000 after 10000000 attempts.
    Try a lower -e value or a longer -l length.

Run `-a` first to discover the achievable range for your settings before setting a fixed floor.

### Set a minimum entropy floor

Accept only passwords whose Shannon score is at or above 68.0:

    $ entpassgen -e 68.0

Using the shorthand notation:

    $ entpassgen -e e8    # floor = 88.0  (e prefix = 80s range)
    $ entpassgen -e n5    # floor = 95.0  (n prefix = 90s range)
    $ entpassgen -e s3    # floor = 73.0  (s prefix = 70s range)

### Analyze with 1 billion samples (slow — shows the spinner)

    $ entpassgen -k 1000000000 -a -j
    Calculating ... 22.4s -

After completion the spinner clears and results appear on stdout.

---

## Performance Benchmarks

| Benchmark | Iterations | Time/Op | Memory/Op | Allocs/Op |
|-----------|----------:|--------:|----------:|----------:|
| `BenchmarkRandomInt` | 43,678,664 | 136.8 ns | 48 B | 3 |
| `BenchmarkCalculateEntropy` (short) | 64,353,802 | 95.00 ns | 0 B | 0 |
| `BenchmarkCalculateEntropy` (long) | 3,091,953 | 1,943 ns | 328 B | 3 |
| `BenchmarkGenerateRandomPassword` (short) | 3,366,054 | 1,791 ns | 816 B | 40 |
| `BenchmarkGenerateRandomPassword` (long) | 668,047 | 9,137 ns | 3,424 B | 197 |
| `BenchmarkGenerateWordPassword` | 3,163,896 | 1,897 ns | 634 B | 31 |

> **Environment:** darwin/arm64 · Apple M3 Ultra (GOMAXPROCS = 28)

**Column guide:**
- **Iterations** — how many times the loop ran; higher = faster function.
- **Time/Op** — nanoseconds per call; lower is better.
- **Memory/Op** — heap bytes allocated per call; zero means stack-only.
- **Allocs/Op** — distinct heap allocations per call; high counts increase GC pressure.

---

## Building from source

    make help       # list all targets

    # Development
    make ci         # clean + vet + lint + unit + bench + fuzz + build
    make build      # compile binary to bin/entpassgen
    make run        # run directly via go run (pass ARGS="-q 5" etc.)

    # Testing
    make unit       # unit tests with race detector
    make bench      # benchmark tests
    make fuzz       # fuzz tests (20s per target)
    make coverage   # coverage report to outputs/

    # Quality
    make lint       # gofmt
    make vet        # go vet

    # Install
    make install    # build then install to ~/bin/entpassgen
    make installed  # print 'yes' or 'no'
    make uninstall  # remove ~/bin/entpassgen

    # Clean
    make clean      # remove bin/ and outputs/
    make clean-all  # clean + uninstall

    # Release
    make all        # cross-compile for darwin, linux, windows (amd64 + arm64)

> `make install` installs to `~/bin/entpassgen` without requiring `sudo`. If `~/bin` is not in your `PATH`, the Makefile will print a warning with the exact line to add to your shell profile.

---

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).