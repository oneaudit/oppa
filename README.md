<h1 align="center">
  <img src=".github/image.png" alt="oppa" width="100px">
  <br>
  OPPA
</h1>
<h4 align="center">A toolkit to generate OpenAPI specifications.</h4>

## Installation ✍️

oppa requires **Go 1.23.0+** to install successfully.

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
   -t, -target string          target input file to parse
   -im, -input-mode string     mode of input file (jsonl, logger++) (default "jsonl")
   -sr, -server-root string[]  Manually define server roots.

CONFIGURATION:
   -config string  path to the oppa configuration file

TUNING:
   -no-origin, -n                     By default, oppa adds an Origin header to all paths.
   -keep-404, -k4                     By default, oppa skips file endpoint with a 404 code.
   -filter-regex, -fr string[]        Skip endpoints based on a regex.
   -filter-regex-base, -frb string[]  Skip endpoints based on a regex.

OUTPUT:
   -d, -output-dir string  store openapi to custom directory
   -silent                 display output only
   -v, -verbose            display verbose output
   -debug                  display debug output
   -version                display project version
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

## Examples

On a GLPI project with directory listing, we can use:

```command
oppa -config config.yaml -target katana.txt -fr "^/icons/" -fr "^/src/" -fr "^/pics/" -fr "^/templates/" -fr "^/css_compiled/"
```