#!/usr/bin/env bash

set -Euo pipefail
IFS=$' \t\n'
# (macOS bash 3.2 safety)
declare -a PARSE_EXCLUDE_FILES=()

export LC_ALL=C LANG=C

readonly EXIT_SUCCESS=0
readonly EXIT_INVALID_ARGS=1
readonly EXIT_CONFIG_ERROR=2
readonly EXIT_DEPENDENCY_ERROR=3
readonly EXIT_PERMISSION_ERROR=4
readonly EXIT_PATH_ERROR=5
readonly EXIT_PATH_TRAVERSAL=50
readonly EXIT_PATH_NULL=51
readonly EXIT_PATH_LENGTH=52
readonly EXIT_PATH_DANGEROUS_CHARS=53
readonly EXIT_JSON_ERROR=6

readonly CONFIG_COMMIT_SHA="114d98de8df092bb062b3a1d0c17c7d8a78ebce7"
readonly DEFAULT_MAX_LINES=1999
readonly PATH_MAX_SAFE=4096
readonly LINE_WIDTH_LIMIT=120
readonly EXTRACT_AWK_DEFAULT=true
readonly EXCLUDE_DIRS_DEFAULT=("node_modules" "vendor" ".git" "venv")

log() {
	local level="$1"
	shift || true
	case "$level" in
	DEBUG)
		[[ "${DEBUG:-false}" == "true" ]] || return 0
		;;
	INFO | ERROR) ;;
	*) return 0 ;;
	esac
	printf '%s: %s\n' "$level" "$*" >&2
}

log_debug() { log DEBUG "$*"; }
log_info() { log INFO "$*"; }
log_error() { log ERROR "$*"; }

fail() {
	local code="$1"
	shift || true
	log ERROR "$*"
	exit "$code"
}

show_usage() {
	cat <<'EOF'
Usage: ext.sh [--debug] [--include-tests] [--exclude <file>] <folder|file>

Options:
  --debug           Enable debug output
  --include-tests   Include test files in analysis
  --exclude <file>  Exclude specific filename from analysis
  -h, --help        Show this help

Arguments:
  <folder|file>     Target directory or file to process
EOF
}

parse_args() {
	PARSE_DEBUG="false"
	PARSE_INCLUDE_TESTS="false"
	PARSE_TARGET_PATH=""
	PARSE_EXCLUDE_FILES=()

	while (($#)); do
		case "$1" in
		--debug)
			PARSE_DEBUG="true"
			shift
			;;
		--include-tests)
			PARSE_INCLUDE_TESTS="true"
			shift
			;;
		--exclude)
			if [[ -z "${2:-}" || "$2" == --* ]]; then
				log_error "--exclude requires a filename argument"
				show_usage
				exit "$EXIT_INVALID_ARGS"
			fi
			PARSE_EXCLUDE_FILES+=("$2")
			shift 2
			;;
		-h | --help)
			show_usage
			exit 0
			;;
		-*)
			log_error "Unknown option: $1"
			show_usage
			exit "$EXIT_INVALID_ARGS"
			;;
		*)
			if [[ -n "$PARSE_TARGET_PATH" ]]; then
				log_error "Multiple target paths specified"
				show_usage
				exit "$EXIT_INVALID_ARGS"
			fi
			PARSE_TARGET_PATH="$1"
			shift
			;;
		esac
	done
}

has_gnu_realpath() {
	command -v realpath >/dev/null 2>&1 || return 1
	realpath --help 2>&1 | grep -q -- '--relative-to' 2>/dev/null || return 1
}

realpath_safe() {
	local path="$1"
	if command -v realpath >/dev/null 2>&1; then
		realpath "$path"
	elif command -v grealpath >/dev/null 2>&1; then
		grealpath "$path"
	elif command -v python3 >/dev/null 2>&1; then
		python3 -c "import os,sys; print(os.path.abspath(sys.argv[1]))" "$path"
	elif command -v python >/dev/null 2>&1; then
		python -c "import os,sys; print(os.path.abspath(sys.argv[1]))" "$path"
	else
		readlink -f "$path" 2>/dev/null || {
			log_error "No suitable realpath implementation found"
			return 1
		}
	fi
}

sanitize_path() {
	local path="$1"
	if [[ "$path" == *".."* ]]; then
		log_error "Path contains directory traversal sequences: $path"
		return "$EXIT_PATH_TRAVERSAL"
	fi
	if [[ "$path" =~ [$'\n'$'\r'] ]]; then
		log_error "Path contains newline or carriage return characters: $path"
		return "$EXIT_PATH_DANGEROUS_CHARS"
	fi
	if ((${#path} > PATH_MAX_SAFE)); then
		log_error "Path exceeds maximum length ($PATH_MAX_SAFE): $path"
		return "$EXIT_PATH_LENGTH"
	fi
	if [[ "$path" =~ [\;\|\&\`\<\>\{\}] ]]; then
		log_error "Path contains potentially dangerous shell metacharacters: $path"
		return "$EXIT_PATH_DANGEROUS_CHARS"
	fi
	return 0
}

validate_file_permissions() {
	local file="$1"
	local check_write="${2:-false}"

	[[ -r "$file" ]] || {
		log_error "File is not readable: $file"
		return 1
	}

	if [[ "$check_write" == "true" && "$file" == *".gitignore" && -f "$file" ]]; then
		[[ -w "$file" ]] || {
			log_error "Cannot write to .gitignore file: $file"
			return 1
		}
		local file_owner
		if [[ "$(uname)" == "Darwin" ]]; then
			file_owner=$(stat -f '%Su' "$file" 2>/dev/null) || {
				log_error "Cannot determine owner of file: $file"
				return 1
			}
		else
			file_owner=$(stat -c '%U' "$file" 2>/dev/null) || {
				log_error "Cannot determine owner of file: $file"
				return 1
			}
		fi
		[[ "$file_owner" == "$(whoami)" ]] || {
			log_error "File not owned by current user, refusing to modify: $file"
			return 1
		}
	fi
	return 0
}

validate_target() {
	local target="$1"
	[[ -n "$target" ]] || {
		log_error "No target path specified"
		show_usage
		exit "$EXIT_INVALID_ARGS"
	}

	local sp_code=0
	sanitize_path "$target" || sp_code=$?
	if ((sp_code != 0)); then
		exit "$sp_code"
	fi

	local resolved
	resolved=$(realpath_safe "$target") || {
		log_error "Cannot resolve absolute path for: $target"
		exit "$EXIT_PATH_ERROR"
	}

	local is_file="false"
	if [[ -f "$resolved" ]]; then
		is_file="true"
	elif [[ -d "$resolved" ]]; then
		is_file="false"
		if [[ ! -x "$resolved" ]]; then
			log_error "Directory is not traversable (missing execute permission): $resolved"
			exit "$EXIT_PERMISSION_ERROR"
		fi
	else
		log_error "Target path is neither a valid file nor directory: $resolved"
		exit "$EXIT_PATH_ERROR"
	fi

	validate_file_permissions "$resolved" || exit "$EXIT_PERMISSION_ERROR"

	TARGET_PATH="$resolved"
	IS_FILE="$is_file"
}

create_merged_ignore_file() {
	local scan_root="$1"
	local temp_ignore

	temp_ignore="/tmp/global-extractor-ignore-$$"
	log_debug "Creating temporary merged ignore file: $temp_ignore"

	local user_gitignore="$scan_root/.gitignore"
	if [[ -f "$user_gitignore" && -r "$user_gitignore" ]]; then
		log_debug "Adding user's .gitignore patterns from: $user_gitignore"
		cp "$user_gitignore" "$temp_ignore" || {
			log_error "Failed to copy user's .gitignore"
			return 1
		}
		echo "" else >>"$temp_ignore"
		touch "$temp_ignore" || {
			log_error "Failed to create temporary ignore file"
			return 1
		}
	fi

	if [[ -f "$IGNORE_DB" && -r "$IGNORE_DB" ]]; then
		log_debug "Adding global ignore patterns from: $IGNORE_DB"
		echo "" >>"$temp_ignore"
		cat "$IGNORE_DB" >>"$temp_ignore" || {
			log_error "Failed to append global ignore patterns"
			rm -f "$temp_ignore"
			return 1
		}
	fi

	TEMP_IGNORE_FILE="$temp_ignore"
	return 0
}

matches_ignore_pattern() {
	local file="$1"
	local pattern="$2"
	local filename

	filename=$(basename "$file")

	case "$pattern" in
	"")
		return 1
		;;
	"#"*)
		return 1
		;;
	"*"*)
		if [[ "$filename" == $pattern ]]; then
			return 0
		fi
		if [[ "$file" == *$pattern ]]; then
			return 0
		fi
		;;
	*/*)
		if [[ "$file" == *"$pattern"* ]]; then
			return 0
		fi
		;;
	*)
		if [[ "$filename" == "$pattern" ]]; then
			return 0
		fi
		;;
	esac

	return 1
}

check_ignore_patterns() {
	local file="$1"
	local pattern

	[[ -n "${TEMP_IGNORE_FILE:-}" && -f "$TEMP_IGNORE_FILE" ]] || return 1

	while IFS= read -r pattern; do
		[[ -n "$pattern" && "$pattern" != "#"* ]] || continue

		if matches_ignore_pattern "$file" "$pattern"; then
			log_debug "File matches ignore pattern '$pattern': $file"
			return 0
		fi
	done <"$TEMP_IGNORE_FILE"

	return 1
}

in_git_repo() {
	local root="$1"
	git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1
}

safe_git_check_ignore() {
	local file="$1"
	local abs_path
	local repo_root

	sanitize_path "$file" || return 1
	abs_path=$(realpath_safe "$file") || {
		log_debug "Cannot resolve absolute path for: $file"
		return 1
	}
	repo_root=$(git -C "$(dirname "$abs_path")" rev-parse --show-toplevel 2>/dev/null) || return 1

	if [[ -n "${TEMP_IGNORE_FILE:-}" && -f "$TEMP_IGNORE_FILE" ]]; then
		git -C "$repo_root" check-ignore --exclude-from="$TEMP_IGNORE_FILE" -q "$abs_path" 2>/dev/null
	else
		git -C "$repo_root" check-ignore -q "$abs_path" 2>/dev/null
	fi
}

get_config_path() {
	local base_dir
	local fallback_dir
	base_dir="${XDG_CONFIG_HOME:-$HOME/.config}/global-extractor"
	fallback_dir="$HOME/bin"

	if [[ -d "$base_dir" ]]; then
		printf '%s\n' "$base_dir"
		return 0
	fi
	if mkdir -p "$base_dir"; then
		printf '%s\n' "$base_dir"
		return 0
	fi

	if [[ -d "$fallback_dir" && -O "$fallback_dir" ]]; then
		printf '%s\n' "$fallback_dir"
		return 0
	fi

	log_error "Cannot find or create safe config directory"
	return "$EXIT_CONFIG_ERROR"
}

validate_json() {
	local json_file
	json_file="$1"
	jq empty "$json_file" >/dev/null 2>&1 || return 1
	jq -e 'type == "object"' "$json_file" >/dev/null 2>&1 || return 1
	return 0
}

download_config() {
	log_info "First run detected. Downloading configuration files..."

	local ext_json_url="https://raw.githubusercontent.com/diegomrepo/global-extractor/${CONFIG_COMMIT_SHA}/ext.json"
	local ext_ignore_url="https://raw.githubusercontent.com/diegomrepo/global-extractor/${CONFIG_COMMIT_SHA}/ext.ignore"

	if ! mkdir -p "$CONFIG_DIR"; then
		log_error "Failed to create config directory: $CONFIG_DIR"
		return 1
	fi

	local script_dir
	script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

	if [[ -f "$script_dir/ext.json" ]]; then
		log_info "Copying ext.json from local repository..."
		if cp "$script_dir/ext.json" "$DB"; then
			log_info "ext.json copied successfully from local repository"
		else
			log_debug "Local ext.json copy failed; falling back to network download"
		fi
	fi

	if [[ ! -f "$DB" ]]; then
		log_info "Downloading ext.json..."
		if command -v curl >/dev/null 2>&1; then
			curl --connect-timeout 10 --max-time 30 -sSfL "$ext_json_url" -o "$DB" || {
				log_error "Failed to download ext.json via curl"
				return 1
			}
		elif command -v wget >/dev/null 2>&1; then
			wget --timeout=30 --tries=2 -q "$ext_json_url" -O "$DB" || {
				log_error "Failed to download ext.json via wget"
				return 1
			}
		else
			log_error "Neither curl nor wget is available"
			return 1
		fi
	fi

	if [[ ! -r "$DB" ]] || ! validate_json "$DB"; then
		log_error "Downloaded ext.json is invalid or unreadable"
		return 1
	fi

	if [[ -f "$script_dir/ext.ignore" ]]; then
		log_info "Copying ext.ignore from local repository..."
		if cp "$script_dir/ext.ignore" "$IGNORE_DB"; then
			log_info "ext.ignore copied successfully from local repository"
		else
			log_debug "Local ext.ignore copy failed; falling back to network download"
		fi
	fi

	if [[ ! -f "$IGNORE_DB" ]]; then
		log_info "Downloading ext.ignore..."
		if command -v curl >/dev/null 2>&1; then
			curl --connect-timeout 10 --max-time 30 -sSfL "$ext_ignore_url" -o "$IGNORE_DB" || {
				log_error "Failed to download ext.ignore via curl"
				return 1
			}
		elif command -v wget >/dev/null 2>&1; then
			wget --timeout=30 --tries=2 -q "$ext_ignore_url" -O "$IGNORE_DB" || {
				log_error "Failed to download ext.ignore via wget"
				return 1
			}
		else
			log_error "Neither curl nor wget is available"
			return 1
		fi
	fi

	if [[ ! -r "$IGNORE_DB" ]]; then
		log_error "Downloaded ext.ignore is invalid or unreadable"
		return 1
	fi

	log_info "Configuration files downloaded successfully"
	return 0
}

check_dependencies() {
	local missing=()

	command -v git >/dev/null 2>&1 || missing+=("git")
	command -v jq >/dev/null 2>&1 || missing+=("jq")
	if ! command -v realpath >/dev/null 2>&1; then
		if [[ "$(uname)" == "Darwin" ]]; then
			if command -v grealpath >/dev/null 2>&1; then
				alias realpath=grealpath
			else
				missing+=("realpath/grealpath (brew install coreutils)")
			fi
		else
			missing+=("realpath")
		fi
	fi
	command -v grep >/dev/null 2>&1 || missing+=("grep")
	command -v find >/dev/null 2>&1 || missing+=("find")
	if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
		missing+=("curl or wget")
	fi

	if ((${#missing[@]} > 0)); then
		log_error "Missing required dependencies: ${missing[*]}"
		exit "$EXIT_DEPENDENCY_ERROR"
	fi

	if [[ ! -r "$DB" ]]; then
		log_info "Extension database not found or not readable: $DB"
		download_config || fail "$EXIT_CONFIG_ERROR" "Failed to obtain configuration files"
	fi

	validate_json "$DB" || fail "$EXIT_JSON_ERROR" "Invalid JSON format in $DB"

	local tmp_ext
	if ! tmp_ext=$(jq -r 'keys | .[]' "$DB" 2>/dev/null); then
		fail "$EXIT_JSON_ERROR" "Failed to parse extensions from $DB"
	fi
	[[ -n "$tmp_ext" ]] || fail "$EXIT_JSON_ERROR" "No valid extensions found in $DB"

	VALID_EXTENSIONS="$tmp_ext"
	VALID_EXTENSIONS_LOWER=$(printf '%s\n' "$VALID_EXTENSIONS" | tr '[:upper:]' '[:lower:]')
}

list_candidate_files() {
	local scan_root="$1"
	local repo_root

	if in_git_repo "$scan_root"; then
		repo_root=$(git -C "$scan_root" rev-parse --show-toplevel 2>/dev/null) || {
			log_error "Failed to determine git repository root"
			return 1
		}

		if [[ -n "${TEMP_IGNORE_FILE:-}" && -f "$TEMP_IGNORE_FILE" ]]; then
			while IFS= read -r -d '' file; do
				local abs_file="$repo_root/$file"
				if [[ "$abs_file" == "$scan_root"* ]]; then
					printf '%s\0' "$abs_file"
				fi
			done < <(git -C "$repo_root" ls-files -z --cached --others --exclude-from="$TEMP_IGNORE_FILE")
		else
			while IFS= read -r -d '' file; do
				local abs_file="$repo_root/$file"
				if [[ "$abs_file" == "$scan_root"* ]]; then
					printf '%s\0' "$abs_file"
				fi
			done < <(git -C "$repo_root" ls-files -z --cached --others --exclude-standard)
		fi
	else
		local find_args
		find_args=("$scan_root")
		local d
		for d in "${EXCLUDE_DIRS[@]}"; do
			find_args+=(-name "$d" -prune -o)
		done
		find_args+=(-type f -print0)
		find "${find_args[@]}" 2>/dev/null
	fi
}

should_skip_file() {
	local file="$1"

	sanitize_path "$file" || return 0
	[[ -r "$file" ]] || return 0

	if safe_git_check_ignore "$file"; then
		return 0
	fi

	if ! in_git_repo "$(dirname "$file")" && check_ignore_patterns "$file"; then
		return 0
	fi

	if ((${#EXCLUDE_FILES[@]} > 0)); then
		local filename
		filename=$(basename "$file")
		local pat
		for pat in "${EXCLUDE_FILES[@]}"; do
			if [[ "$filename" == "$pat" ]]; then
				return 0
			fi
		done
	fi

	if [[ "$INCLUDE_TESTS" == "false" ]]; then
		local filename
		filename=$(basename "$file")
		local lower
		lower=$(printf '%s' "$filename" | tr '[:upper:]' '[:lower:]')
		if [[ "$lower" == *test* || "$lower" == *spec* || "$lower" == *_test.* || "$lower" == *.test.* || "$lower" == *_spec.* || "$lower" == *.spec.* ]]; then
			return 0
		fi
	fi

	local extension
	extension="${file##*.}"
	if [[ -z "$extension" ]]; then
		return 0
	fi
	local extension_lower
	extension_lower=$(printf '%s' "$extension" | tr '[:upper:]' '[:lower:]')
	if ! printf '%s\n' "$VALID_EXTENSIONS_LOWER" | grep -q -w "$extension_lower"; then
		return 0
	fi

	return 1
}

print_header() {
	if [[ "$IS_FILE" == "true" ]]; then
		echo "The following output lists, for this source file, all root-level (line 0, no leading whitespace) statements."
	else
		echo "The following output lists, for each source file, all root-level (line 0, no leading whitespace) statements."
	fi
}

extract_root_statements_awk() {
	local file="$1"
	awk -v w="$LINE_WIDTH_LIMIT" '
        /^[^[:space:]].*[[:alpha:]]/ {
            line=$0
                        if (line ~ /^(#|\/\/|\/\*|\*|;|import|from|!|-|")/) next
            if (length(line) > w) next
                        lower=tolower(line)
            if (lower ~ /(^|[^[:alnum:]_])mock([^[:alnum:]_]|$)/) next
            print line
        }
    ' "$file"
}

process_file() {
	local file="$1"
	local root="$2"
	local use_awk="$3"

	if should_skip_file "$file"; then
		return
	fi

	if ! grep -Iq . "$file" 2>/dev/null; then
		log_debug "Skipping binary file: $file"
		return
	fi

	local relative_path=""
	if [[ "${HAVE_GNU_REALPATH:-false}" == "true" ]]; then
		if ! relative_path=$(realpath --relative-to="$root" "$file" 2>/dev/null); then
			log_debug "GNU realpath relative path failed for: $file (falling back)"
			relative_path=""
		fi
	fi

	if [[ -z "$relative_path" ]]; then
		local abs_file abs_root
		abs_file=$(realpath_safe "$file") || {
			log_error "Cannot resolve absolute path for file: $file"
			return
		}
		abs_root=$(realpath_safe "$root") || {
			log_error "Cannot resolve absolute path for root: $root"
			return
		}
		if [[ "$abs_file" == "$abs_root/"* ]]; then
			relative_path="${abs_file#$abs_root/}"
		else
			relative_path=$(basename "$file")
		fi
	fi

	local matches
	if [[ "$use_awk" == "true" ]]; then
		matches=$(extract_root_statements_awk "$file") || matches=""
	else
		matches=$(grep -E '^[^[:space:]].*[[:alpha:]]' "$file" 2>/dev/null |
			grep -Ev '^(#|//|/\*|\*|;|import|from|!|-|")' |
			grep -E "^.{1,${LINE_WIDTH_LIMIT}}$" |
			grep -ivE '(^|[^[:alnum:]_])mock([^[:alnum:]_]|$)' || true)
	fi

	[[ -z "${matches:-}" ]] && return

	printf '==> %s <==\n' "$relative_path"
	printf '%s\n' "$matches"
	local n
	n=$(printf '%s\n' "$matches" | wc -l | tr -d ' ')
	LINE_COUNT=$((LINE_COUNT + n))
}

process_directory() {
	local target="$1"
	local root="$2"
	local max_lines="$3"
	local use_awk="$4"

	local file
	while IFS= read -r -d '' file; do
		process_file "$file" "$root" "$use_awk"
		if ((LINE_COUNT >= max_lines)); then
			break
		fi
	done < <(list_candidate_files "$target")
}

cleanup() {
	if [[ -n "${TEMP_IGNORE_FILE:-}" && -f "$TEMP_IGNORE_FILE" ]]; then
		log_debug "Cleaning up temporary ignore file: $TEMP_IGNORE_FILE"
		rm -f "$TEMP_IGNORE_FILE"
	fi
}

trap cleanup EXIT

main() {
	parse_args "$@"

	DEBUG="$PARSE_DEBUG"
	INCLUDE_TESTS="$PARSE_INCLUDE_TESTS"
	TARGET_PATH=""
	IS_FILE="false"
	EXCLUDE_FILES=("${PARSE_EXCLUDE_FILES[@]-}")
	EXCLUDE_DIRS=("${EXCLUDE_DIRS_DEFAULT[@]}")
	VALID_EXTENSIONS=""
	LINE_COUNT=0
	TEMP_IGNORE_FILE=""

	CONFIG_DIR="$(get_config_path)" || exit "$?"
	readonly CONFIG_DIR
	DB="$CONFIG_DIR/ext.json"
	IGNORE_DB="$CONFIG_DIR/ext.ignore"
	readonly DB IGNORE_DB

	validate_target "$PARSE_TARGET_PATH"

	if [[ "$IS_FILE" == "true" ]]; then
		SCAN_ROOT=$(dirname "$TARGET_PATH")
	else
		SCAN_ROOT="$TARGET_PATH"
	fi
	readonly SCAN_ROOT

	MAX_LINES="${MAX_LINES:-$DEFAULT_MAX_LINES}"
	USE_AWK="${USE_AWK_EXTRACT:-$EXTRACT_AWK_DEFAULT}"

	check_dependencies

	if has_gnu_realpath; then
		HAVE_GNU_REALPATH=true
	else
		HAVE_GNU_REALPATH=false
	fi
	readonly HAVE_GNU_REALPATH

	if [[ "$IS_FILE" == "false" ]]; then
		create_merged_ignore_file "$SCAN_ROOT" || {
			log_error "Failed to create merged ignore file"
			exit "$EXIT_CONFIG_ERROR"
		}
	fi

	print_header

	if [[ "$IS_FILE" == "true" ]]; then
		process_file "$TARGET_PATH" "$SCAN_ROOT" "$USE_AWK"
	else
		process_directory "$TARGET_PATH" "$SCAN_ROOT" "$MAX_LINES" "$USE_AWK"
	fi
}

main "$@"
exit "$EXIT_SUCCESS"
