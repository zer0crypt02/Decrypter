<picture align="left">
  <img width="500" height="500" alt="Remove Background Image" src="https://github.com/user-attachments/assets/261cdef9-f5c2-4449-a7e2-83ee3a5e8d31" />
</picture>

# Decrypter

> **Hex & XOR Decoder — Reverse Engineering Helper**  
> Hexadecimal conversions, single-byte XOR decoding, and 256-key brute-force all in one CLI tool.

---

## Features

| Mode | Description |
|------|-------------|
| `--hex <str>` | Decode hex string into ASCII + Decimal table |
| `--tohex <text>` | Convert ASCII text to hex |
| `--dec <hex>` | Convert hex value to decimal |
| `<hex>` (single arg) | XOR brute-force: tries all 256 keys, shows only readable output |
| `<hex> <key>` (two args) | XOR decode with a known single-byte key |

---

## Code Analysis

### 1. `hex_to_bytes(hex_str)` — Hex → Byte conversion

```python
def hex_to_bytes(hex_str):
    h = hex_str.replace(" ", "").replace("0x", "")
    return bytes(int(h[i : i + 2], 16) for i in range(0, len(h), 2))
```

- Strips spaces and `0x` prefixes.
- Parses every two hex characters as a byte via `int(..., 16)`.
- Flexible input: `"5B 49 5C"`, `"5B495C"`, or `"0x5B 0x49"` — all work.

### 2. `ascii_to_hex(text)` — ASCII → Hex conversion

```python
def ascii_to_hex(text):
    return " ".join(f"{ord(c):02X}" for c in text)
```

- Takes each character's Unicode code point and formats it as `%02X`.
- Example: `"Hello"` → `"48 65 6C 6C 6F"`

### 3. `xor_decode(data, key)` — XOR operation

```python
def xor_decode(data, key):
    return bytes(b ^ key for b in data)
```

- XORs every byte with a single `key` value.
- `data: bytes`, `key: int` (0–255).
- **Single-byte XOR** — one of the most common obfuscation techniques in malware.

### 4. `brute_force(data)` — Brute-force all key candidates

```python
def brute_force(data):
    found = 0
    for k in range(256):
        r = xor_decode(data, k)
        if all(32 <= b < 127 for b in r):
            found += 1
            print(f"  XOR 0x{k:02X} ({key_char}) -> {r.decode()}")
    if found == 0:
        print("  (no readable results found)")
```

- Iterates over **all 256 possible single-byte keys**.
- Filters results to only those where **every byte is printable ASCII** (space `32` through `126` `~`).
- This filter makes it trivial to spot embedded strings in XOR-obfuscated malware payloads.
- If no readable output is found, it clearly reports failure.

### 5. `show_hex_decode(hex_str)` — Detailed Hex → ASCII table

```python
def show_hex_decode(hex_str):
    data = hex_to_bytes(hex_str)
    print(f"  {'Hex':>5}  {'Dec':>4}  {'Char'}")
    for b in data:
        c = chr(b) if 32 <= b < 127 else "."
        print(f"  0x{b:02X}  {b:>4}  {c}")
```

- Displays Hex, Decimal, and ASCII columns side by side in a formatted table.
- Non-printable bytes are shown as `.`.

### 6. `main()` — CLI entry point

```python
if args[0] == "--dec":       # hex → decimal
    val = int(args[1], 16)
elif args[0] == "--hex":     # hex → ASCII table
    show_hex_decode(args[1])
elif args[0] == "--tohex":   # ASCII → hex
    show_tohex(" ".join(args[1:]))
else:
    data = hex_to_bytes(args[0])
    if len(args) >= 2:       # XOR with known key
        key = int(args[1], 16)
        xor_decode(data, key)
    else:                    # brute-force
        brute_force(data)
```

Argument dispatch logic:
1. **No arguments** → prints `__doc__` (usage help).
2. **`--dec <hex>`** → hex to decimal.
3. **`--hex <hex>`** → detailed conversion table.
4. **`--tohex <text>`** → ASCII to hex.
5. **`<hex>` alone** → XOR brute-force (unknown key).
6. **`<hex> <key>`** → XOR decode with known key.

---

## Usage

### Hex → ASCII (straight decode)
```bash
python3 xor_decoder.py --hex "48656C6C6F"
```

```
=== HEX -> DECIMAL -> ASCII ===
   Hex    Dec  Char
  -----  ----  ----
  0x48    72  H
  0x65   101  e
  0x6C   108  l
  0x6C   108  l
  0x6F   111  o

  Hex:      48 65 6C 6C 6F
  Decimal:   72 101 108 108 111
  ASCII:    Hello
```

### XOR decode with known key
```bash
python3 xor_decoder.py "5B 49 5C 50 56 58" 0x1A
```

```
  XOR 0x1A -> b'ASCRP'
               -> ASCRP
```

> The output shows both the raw `bytes` literal and the decoded string on a second line.

### XOR brute-force (unknown key)
```bash
python3 xor_decoder.py "5B495C505658"
```

```
  Hex: 5B 49 5C 50 56 58
  Raw: [_ I \ P V X ]

  XOR 0x1A (?) -> ASCRP
  XOR 0x3A (:) -> aSCRP
  XOR 0x5A (Z) -> \x01\x03\x06\x00\x0c\x02
  ...
```

> Only **fully readable** results are displayed.  
> If no key produces readable output, it prints `(no readable results found)`.

### ASCII → Hex (reverse conversion)
```bash
python3 xor_decoder.py --tohex Hello World
```

```
  "Hello World" -> 48 65 6C 6C 6F 20 57 6F 72 6C 64
```

### Hex → Decimal
```bash
python3 xor_decoder.py --dec FF
```

```
  FF = 255
```

---

## Use Cases

| Area | Description |
|------|-------------|
| **🔬 Malware Analysis** | Decode XOR-obfuscated strings and config blocks in malware samples |
| **🛡️ Reverse Engineering** | Convert embedded hex data in binaries to readable ASCII |
| **🔑 CTF Competitions** | Single-byte XOR cracking in Capture The Flag challenges |
| **🧪 Protocol Analysis** | Turn hex dumps into human-readable text |
| **🔧 Debugging** | Inspect hex data from memory dumps or network packets |

---

## Requirements

- **Python 3.6+** (stdlib only — zero external dependencies)
- OS: Windows / macOS / Linux (works identically on all platforms)

---

## Project Structure

```
Test01/
├── xor_decoder.py                # Main tool (this script)
├── Remove Background Image.png   # Logo
├── Malware Sample.zip            # Sample for analysis
├── Malware Sample2.zip           # Sample for analysis
├── malware_samples/              # Additional samples
└── *.dll                         # DLLs for analysis
```

> **Warning**: `.zip` and `.dll` files may contain malicious software.  
> Only inspect them in an **isolated / sandboxed environment**.

---

## Extension Ideas

- **Multi-byte XOR** support (repeating-key / Vigenere-style)
- **File input**: `--file dump.bin` to read binary files directly
- **Output to file**: `--output` argument for saving results
- **Entropy analysis**: Compare entropy before and after XOR
- **Colorized output**: Highlight readable vs non-printable bytes in the terminal

---

> **Disclaimer**: This tool is intended for **educational purposes, forensic analysis, and security research only**.  
> Any malicious use is prohibited by law.
