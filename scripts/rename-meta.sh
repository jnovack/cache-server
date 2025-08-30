#!/usr/bin/env bash
set -euo pipefail

# Starting directory (default to current dir if not passed)
root="${1:-.}"

# Find all {filename}.meta.json files
find "$root" -type f -name '*.meta.json' | while IFS= read -r file; do
    dir=$(dirname "$file")
    base=$(basename "$file")
    # Skip if it already starts with a dot
    if [[ $base != .* ]]; then
        # Rename to .{filename}.meta.json
        new="$dir/.$base"
        echo "Renaming: $file -> $new"
        mv -- "$file" "$new"
    fi
done