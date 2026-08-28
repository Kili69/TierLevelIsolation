# Repository instructions

## Versioning on commits

- Before creating any commit, inspect every file included in that commit.
- If a changed file already contains its own current version number, update that version number as part of the same commit.
- Use the format `<major>.<minor>.<yyyyMMdd>.<counter>`.
- Preserve the file's existing `major` and `minor` values unless the requested change explicitly requires a major or minor version bump.
- Use the commit date for `yyyyMMdd`.
- Set `counter` to `1` when the date changes; increment the existing counter when another version is created on the same date.
- Keep all active/current version declarations within the same file consistent, for example a metadata version and a `$ScriptVersion` variable.
- Do not rewrite older version-history entries. Add a new history entry only when the file already maintains a version history.
- Files without an existing file-specific version number do not require a version number to be added.
- Do not create the commit until all applicable changed files use the required version format.