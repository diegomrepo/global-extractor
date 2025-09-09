# Global Extractor

The script extracts root-level statements (eg function and class definitions) from source files. It's designed to provide a concise, high-level overview of a codebase, which is particularly useful for feeding to LLMs.

## Features

- Extracts root-level statements from source files.
- Skips comments, imports, and boilerplate.
- Ignores files listed in `.gitignore` and a global ignore file.
- Automatically skips test files (but can be included via a flag).
- Supports a wide range of languages via a configurable extension list.
- Processes single files or entire directories.

## Installation

Just copy the `ext.sh` file to a directory in your PATH and make it executable.

## OS Support

The script is designed to work on Unix-like systems and has been tested on:

- **Linux**
- **macOS**
- **Windows Subsystem for Linux (WSL)** (not tested but should work)

[jq](https://stedolan.github.io/jq/) is a dependency.

## Usage

```bash
ext.sh [options] <folder|file>
```

**Arguments:**

-   `<folder|file>`: The target directory or file to process.

**Options:**

-   `--include-tests`: Include test files in the analysis.
-   `--exclude <file>`: Exclude a specific filename from the analysis.
-   `--debug`: Enable debug output for troubleshooting.
-   `-h, --help`: Show the help message.

## Example

A typical output looks like this:
```bash
$ ls /path/to/go_project
client/  go.mod  go.sum  README.md

$ ext.sh /path/to/go_project # most languages are supported

==> client/watch.go <==
package client
type Submission struct {
func isWait(verdict string) bool {
func (s *Submission) ParseStatus() string {
func refreshLine(n int, maxWidth int) {
func updateLine(line string, maxWidth *int) string {
func (s *Submission) display(first bool, maxWidth *int) {
func display(submissions []Submission, problemID string, first bool, maxWidth *int, line bool) {
func findCfOffset(body []byte) (string, error) {
func findSubmission(body []byte, n int) ([][]byte, error) {
const ruTime = "02.01.2006 15:04 Z07:00"
const enTime = "Jan/02/2006 15:04 Z07:00"
func parseWhen(raw, cfOffset string) string {
func parseSubmission(body []byte, cfOffset string) (ret Submission, err error) {
func (c *Client) getSubmissions(URL string, n int) (submissions []Submission, err error) {
var colorMap = map[string]color.Attribute{
```

## Configuration

The script uses a configuration directory located at `$XDG_CONFIG_HOME/global-extractor` (falling back to `~/.config/global-extractor`).

-   `ext.json`: A JSON file where keys are the file extensions (e.g., "go", "py") that the script should process.
-   `ext.ignore`: A global ignore file with patterns similar to `.gitignore`.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
Copyright (c) 2025 Diego Marfil.

