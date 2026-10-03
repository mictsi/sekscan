# Semgrep removal — sekscan 0.6.5-preview


Semgrep support was removed in **0.6.5-preview**. Scans, `prepare --all`, update
checks and default prerequisite status no longer select it. The Python runtime
installer, launcher, native self-test and starter rules are no longer shipped.
There is no Semgrep replacement automatically enabled: general multi-language SAST
now requires a separately configured analyzer. Go SAST remains available via gosec.

Older `checks.semgrep` settings (true or false), Semgrep tool definitions and named
Semgrep extensions are ignored with a migration warning. Their unused built-in uv
helper is removed from the effective configuration too. Other scanners, policies,
version pins, custom integrations and database settings are preserved.

An optional cleanup command writes a **new** configuration without retired entries:

```bash
./sekscan config remove-semgrep --home ./workspace \
  --out ./workspace/sekscan-clean.json
./sekscan prepare --home ./workspace \
  --config ./workspace/sekscan-clean.json --all --yes
```

Rebuilding and using the new executable is enough; rewriting the configuration is
not required. Batch manifests still accept the deprecated boolean `semgrep` key as
an ignored compatibility field. The CLI flag `--semgrep` and native `deps test`
command are removed. An explicit `deps install semgrep` request returns a removal
message without downloading anything.

No scan history, findings, scanner files or caches are deleted automatically.
Historical Semgrep findings remain visible; removing a scanner does not establish
that its previous findings were fixed. No SQL migration is required. Old private
Semgrep logs should not be shared or published as normal artifacts.

## Existing workspace example

```bash
# In the extracted source directory, on a connected build machine:
bash scripts/build.sh
./sekscan version

# Use the existing workspace; keep your usual explicit --config when applicable.
./sekscan prepare --home /home/ghost/lab/sekscan --all --yes
./sekscan deps status --home /home/ghost/lab/sekscan --all
```

The source package contains no production executable, scanner downloads or CVE data.
See TESTING.md for validation boundaries. Windows ARM64 and the other five application
release targets are retained. External scanner platform availability remains separate.
