# CORSchecker

CORSchecker checks if a url is vulnerable to Cross-Origin Resource Sharing (CORS)

## Installation

```bash
go install github.com/SpeedyQweku/CORSchecker@v0.0.2
```

## Usage

```bash
CORSchecker -f [urls.txt]
```

## POC

In the poc folder run

```bash
python -m http.server 5555                             
```
