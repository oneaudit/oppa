<h1 align="center">
  <img src=".github/image.png" alt="oppa" width="100px">
  <br>
  OPPA
</h1>
<h4 align="center">A toolkit to generate OpenAPI specifications.</h4>

## Installation ✍️

oppa requires **Go 1.22+** to install successfully.

```console
CGO_ENABLED=1 go install github.com/oneaudit/oppa/cmd/oppa@latest
```

## Usage 📚

```
oppa -h
```

This will display help for the tool. Here are all the switches it supports.

```
Oppa is a toolkit to generate OpenAPI specifications from JSON lines.

Usage:
  oppa [flags]

Flags:
TARGET:
   -t, -target string       target input file to parse
   -im, -input-mode string  mode of input file ([jsonl]) (default "jsonl")

CONFIGURATION:
   -config string  path to the oppa configuration file

OUTPUT:
   -d, -output-dir string            store openapi to custom directory
   -silent                           display output only
   -v, -verbose                      display verbose output
   -debug                            display debug output
   -version                          display project version
```

## Running Oppa 🧪

Oppa implements a strange and unconventional merge logic. Oppa lacks knowledge on the parameters in each request. To avoid losing information, Oppa creates one openapi entry for each unique URL.

* `https://example.com/?page=index`
* `https://example.com/?page=home`

This results in a strange OpenAPI file. This unconventional approach make it easier to test multiple query parameter combinations with [nuclei](https://github.com/projectdiscovery/nuclei) without editing the tool.

```yaml
  /:
    get:
      parameters:
        - in: query
          name: page
          schema:
            default: index
            type: string
      responses:
        default:
          description: ""
  //:
    get:
      parameters:
        - in: query
          name: page
          schema:
            default: home
            type: string
      responses:
        default:
          description: ""
```

### JSON Lines Input

Oppa can work from [Katana](https://github.com/projectdiscovery/katana) JSON Lines output file format. By default, generated files are stored in the `oppa_openapi` folder.

```
$ katana -u https://example.com -jsonl -o requests.txt
$ oppa -im jsonl -t requests.txt
```