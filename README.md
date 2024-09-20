# Entropy (focused) Password Generator

[![Go Report Card](https://goreportcard.com/badge/github.com/andreimerlescu/entpassgen)](https://goreportcard.com/report/github.com/andreimerlescu/entpassgen)
![GitHub Release](https://img.shields.io/github/v/release/andreimerlescu/entpassgen)
![GitHub License](https://img.shields.io/github/license/andreimerlescu/entpassgen)
![GitHub branch status](https://img.shields.io/github/checks-status/andreimerlescu/entpassgen/master)
![GitHub top language](https://img.shields.io/github/languages/top/andreimerlescu/entpassgen)


[Open/Source/Insights @entpassgen](https://deps.dev/go/github.com%2Fandreimerlescu%2Fentpassgen)
[Go Package @entpassgen](https://pkg.go.dev/github.com/andreimerlescu/entpassgen)


This project demonstrates pure Go functionality as it does not use anything but the standard library. The purpose of `entpassgen` is to offer the ability to generate new passwords, but introduce the concept of entropy to the equation when generating new passwords. The package relies on `crypto/rand` to generate random numbers and uses `rune`, which makes it compatible with multiple languages, countries and use-cases. 

## Getting Started

You can either clone the repository, or install the package directory. This repository depends on: 

- **Go** `1.22.5`+

```zsh
# Clone the repository, build then install
git clone git@github.com/andreimerlescu/entpassgen.git
cd entpassgen
make install # OR RUN THESE 4 ⬇︎⬇︎⬇︎⬇︎
go build -o entpassgen entpassgen.go
sudo mv entpassgen /usr/bin/entpassgen
chmod +x /usr/bin/entpassgen
entpassgen -h

# Install using Go
go install github.com/andreimerlescu/entpassgen@latest
entpassgen -h

# Download the binary and move
curl -o ./entpassgen -s https://github.com/andreimerlescu/entpassgen/releases/download/v1.0.0/entpassgen.linux-amd64
chmod +x entpassgen
sudo mv entpassgen /usr/bin/entpassgen
entpassgen -h
```

### Special Instructions for Windows Users

```powershell
# Clone the repository, build then install
git clone git@github.com/andreimerlescu/entpassgen.git
cd entpassgen
go build -o entpassgen.exe entpassgen.go
entpassgen.exe -h

# Install using Go
go install github.com/andreimerlescu/entpassgen@latest
entpassgen.exe -h

# Download the binary and move (run as Administrator)
New-Item -ItemType Directory -Force -Path C:\bin
setx /M PATH "%PATH%;C:\bin"
Invoke-WebRequest "https://github.com/andreimerlescu/entpassgen/releases/download/v1.0.0/entpassgen.windows-amd64.exe" -OutFile c:\bin\entpassgen.exe
entpassgen.exe -h
```


## Use Cases

This utility is designed to be used in many different kind of use cases. It's stable and intended to set it and forget it. The help menu is your friend.

```zsh
$ which entpassgen
/usr/bin/entpassgen

$ entpassgen -h
Usage of entpassgen:
  -E string
        Define exclude symbols in new password
  -L    Do not use lowercase characters in new password
  -N    Do not use numbers in new password
  -S    Do not use symbols in new password
  -U    Do not use uppercase characters in new password
  -W string
        Separate words with these possible characters (default "!@#$%^&*()_+1234567890-=,.></?;:[]|")
  -a    Generate new passwords to get average entropy, min entropy and max entropy calculated for options
  -e string
        Minimum entropy value to accept in new password (default "avg")
  -j    JSON formatted output
  -k int
        Quantity of passwords to generate when calculating average entropy (default 100000)
  -l int
        Character length in new password (default -1)
  -q int
        Quantity of passwords to generate (default = 1) (default 1)
  -s string
        Define acceptable symbols in new password (default "!@#$%^&*()_+=-[]\\{}|;':,./<>?")
  -t    TEXT formatted output (default) (default true)
  -w    Use words (ignores -U -L -S -E -N -s)

```

### Generate 1 New Password (Defaults)

```zsh
$ entpassgen
uLbirj64,oPDaO5^&uLbirj64,oPDaO5^&
```

### Generate 1 New Password (JSON Output)

```zsh
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
    "average": 66.54055868500511,
    "recommended": 68.01371349313044,
    "min": 49.486868301255775,
    "max": 69.48686830125578
  },
  "entropy": {
    "score": 69.48686830125578
  }
}
```

### Generate Bogus Hebrew Words

```zsh
$ entpassgen -L -U -N -S -s "אבגדהוזחטיכלמנסעפצקרשת" -l 12 -q 5
גקגתתעשנפכט
שבגדעהתלנמ
כדעפמכלכחת
כגטששתחטצת
טכלננמנסא

```

### Generate Random Number (9 digits long)

```zsh
$ entpassgen -L -U -S -l 9 
804799183
```

### Generate Random String (A-Za-z0-9 only)

```zsh
$ entpassgen -S
ZxZ8zOoKym8qDdk07
```

### Generate 10 Random Passwords (Defaults)

```zsh
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
```
### Generate Random Password (memorable words)

```zsh
$ entpassgen -w -l 3
misserve(kinematographic]daunii4
```

### Analyze Strong Passwords

```zsh
$ entpassgen -w -a
Entropy Report: 
  Samples: 100000
  Length: 5
  Uppercase: true
  Lowercase: true
  Digits: true
  Symbols: true
  Use Words: true
  Average: 221.935
  Minimum: 141.402
  Maximum: 328.852
  Recommended: 275.393

$ entpassgen -a   
Entropy Report: 
  Samples: 100000
  Length: 17
  Uppercase: true
  Lowercase: true
  Digits: true
  Symbols: true
  Use Words: false
  Average: 66.534
  Minimum: 53.487
  Maximum: 69.487
  Recommended: 68.010
```

### Analyze Strong Passwords with 1 Billion Samples (JSON output)

> **NOTE**: This may take a long time to run!

```zsh
$ entpassgen -k 1000000000 -a -j
Calculating ... 22.4s -
```

Once completed, the line will clear and the results will show: 

```json
{
  "length": 17,
  "uppercase": true,
  "lowercase": true,
  "digits": true,
  "symbols": true,
  "sample": {
    "limit": 1000,
    "average": 66.62700662609565,
    "recommended": 68.05693746367572,
    "min": 57.977093296928835,
    "max": 69.48686830125578
  },
  "entropy": {}
}
```


