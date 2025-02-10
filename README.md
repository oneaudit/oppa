<h1 align="center">
  <img src=".github/image.png" alt="oppa" width="100px">
  <br>
  OPPA
</h1>
<h4 align="center">A toolkit to generate OpenAPI specifications from JSON lines.</h4>

Installation

```console
CGO_ENABLED=1 go install github.com/oneaudit/oppa/cmd/oppa@latest
```

Usage

```sh
oppa -jsonl output.txt
oppa -jsonl output.txt -d example.com
oppa -jsonl output.txt -d example.com -o specs/
```