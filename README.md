# disk.py

A comprehensive, single-file + single-run disk audit tool for large drives. Built for users managing lots of torrent content who need to understand what's on their drive, what's being seeded, what's not, duplicate files that can be replaced by hardlinks, and what's wasting space.

**Zero dependencies** beyond Python 3.9+ standard library. Optional `xxhash` for faster hashing.

**AI Usage** this script was written *entirely* by AI (Claude Sonnet + Opus). While I (mostly) know what I'm going, I've only done some minimal checking of functionality and a security pass. This script is meant for personal use and was not designed with lots of safeguards in mind. I cannot guarantee this script won't fuck up your drive layout, delete files, or some other miserable catastrophe. (Though it really shouldn't). Use at your own risk: I've used it and it has worked fine for me, but that's it. This readme has been fully verified and by me and is accurate.

## What It Does

`disk.py` treats **inodes** as the fundamental unit. Every unique file on disk is an inode; every path to that file (including hardlinks) is tracked individually. For each path, it checks against qBittorrent's Web API whether that path is actively serving a torrent.

This answers questions like:

- Which files are taking up the most space?
- Does every hardlink actually serve a purpose, or are some orphaned?
- Are there true duplicates (same content, different inodes) wasting disk space?
- Which files aren't attached to any torrent?
- How much space could I recover if I cleaned up unused files?

## Quick Start

First-time setup (optional — only needed for qBittorrent/media features): copy `.env.example` to `.env` and fill in your settings. See [Configuration](#configuration).

```bash
cp .env.example .env    # then edit .env (qBittorrent URL/credentials, media dirs, …)

# Minimal — scans the drive, detects duplicates, offers to fix them
python3 disk.py /mnt/data

# With qBittorrent integration
python3 disk.py /mnt/data --qbt-url https://localhost:8080 --qbt-pass mypassword

# With a media library (Plex/Jellyfin) and multiple qBittorrent instances
python3 disk.py /mnt/data --media-dir /mnt/data/Media \
    --qbt-url https://localhost:8080 --qbt-pass mypassword \
    --qbt-instance "https://seedbox:8080|admin|otherpassword"

# Report only, no cleanup prompts
python3 disk.py /mnt/data --no-fix --no-cleanup-orphans --no-cleanup-empty

# Skip metadata files, flag stale content
python3 disk.py /mnt/data --ignore-ext nfo,txt,srt,jpg --stale-days 180

# mergerfs union: just point at it — the branches are discovered and scanned
python3 disk.py /mnt/pool --media-dir /mnt/pool/Media

# Scan two drives at once and find the same file living on both
python3 disk.py /mnt/disk1 /mnt/disk2
```

For repeated use, put your defaults in the `.env` file (see [Configuration](#configuration)) so you can just run:

```bash
python3 disk.py /mnt/data
```

## Output Files

All output is written **next to `disk.py` itself** (the script's own directory) — never inside the tree you scan. This keeps the scanned data untouched, lets you scan read-only or mergerfs-union mounts, and means re-runs share one hash cache. The **first path you scanned** is still recorded inside the reports as the "root" they describe. (Override the cache location with `--hash-db`; the one exception is `--cross-seed`, whose hardlink directory must live on the data filesystem — see [Cross-Seed Directory](#cross-seed-directory).). The JSON Files are provided as extras for further machine consumption if you want to use them.

| File | Description |
|---|---|
| `diskreport.log` | Full terminal output (ANSI codes stripped) |
| `diskreport.html` | Interactive HTML report with sortable tables, search, and dark theme |
| `used_inodes.json` | Inodes considered **used** (all paths serve an active torrent, or reclassified as used via `--media-dir` — see [Media Directory Reclassification](#media-directory-reclassification)) |
| `unused_inodes.json` | Inodes where **no** paths serve a torrent (and not kept by `--media-dir`) |
| `mixed_inodes.json` | Inodes where **some** paths have torrents and some don't |
| `duplicate_files.json` | True duplicate groups (same content, different inodes). Each group carries a `cross_drive` flag |
| `cross_drive_duplicates.json` | Only the duplicate groups whose copies live on **different drives** — can't be hardlinked, so reclaimed by deleting a redundant copy (see [Cross-Drive Duplicates](#cross-drive-duplicates)) |

### HTML Report

The HTML report is a self-contained, zero-dependency file you can open in any browser. It's built as a **triage workspace**, not just a read-only dump — the idea is to open it, work through your files, and export an action list. It includes:

**Viewing**

- Summary stat cards (inodes, real usage, used/unused with size, dup groups + wasted, cross-drive + reclaimable, stale) plus a live "reviewed X / Y" progress chip.
- Content-type breakdown bar you can click to filter the tables to one or more types.
- Tabbed views: **Used / Unused / Mixed / Duplicates**, plus a dedicated **Cross-Drive** tab when the same file is found on more than one drive.
- Sortable columns (size, type, drive, links, last access, modified), a per-row **Drive** column, and a per-tab search box (searches paths, type, drive, inode) that keeps focus as you type.
- Filters per tab: type, drive, torrent state, freshness (with `--stale-days`), min/max size, and review state.
- Color-coded torrent status ([T]/[P]/[no torrent]), stale highlighting, and a `⇄ CROSS-DRIVE` badge on cross-drive groups. A **copy** button on every path.

**Triage**

- Every row has three one-click marks: **✓ keep**, **✗ delete** (candidate for removal), **⊘ hide** (dismiss from view). Rows are tinted by mark.
- **Marks persist in your browser** (localStorage), namespaced to the report's location — so you can close the tab, re-run/re-open the report later, and your keep/delete/hide decisions are still there. (If your browser blocks storage for `file://` pages, a banner says so; marks still work for the session.)
- Hidden rows drop out of view by default (toggle **Show hidden** to see them); the review-state filter also lets you show only Unreviewed / Keep / For-deletion / Hidden.
- **Bulk actions** apply a mark to everything currently matching your filters (e.g. filter to "video, unused, > 5 GB, no torrent" then bulk-mark delete).
- **Bulk by pattern** — a dedicated bar marks (keep/delete/hide/clear) every file matching a name/path pattern across the *whole* report in one action: `*sample*`, `*.nfo`, or `/regex/`, matched against the full path or just the file name, with a live match count and a confirm. This is the fast way to "exclude everything matching *X*". The per-tab search box understands the same `*glob*` and `/regex/` syntax.
- In the Cross-Drive tab, each copy shows its drive and a suggested keeper, with a one-click **"keep this, delete others"** per group.

**Export (turn decisions into action)**

- From the **Export** menu: download a **delete list** (`.txt` of all paths marked delete), a **delete script** (`.sh` with `rm` lines, shell-quoted and disarmed with `echo` until you review it), a **keep list**, a **marks backup** (`.json`), or the **current tab as CSV**. You can also copy the delete paths to the clipboard.

**Nothing in the HTML ever touches your files** — it only records decisions and exports lists/scripts for you to run.

### JSON Structure

Each inode entry in the JSON reports contains:

```json
{
  "inode": 12345,
  "size_bytes": 1073741824,
  "size_human": "1.0 GB",
  "content_type": "video",
  "link_count": 2,
  "fs_link_count": 2,
  "drive": "/mnt/disk1",
  "mtime": "2025-06-15 14:30:00",
  "atime": "2026-01-10 08:15:00",
  "mtime_epoch": 1718458200.0,
  "atime_epoch": 1736496900.0,
  "stale": false,
  "paths": [
    {
      "path": "/mnt/data/torrents/Movie.mkv",
      "torrents": [
        {
          "torrent_name": "Movie.2024.1080p",
          "torrent_hash": "abc123...",
          "torrent_state": "uploading",
          "active": true
        }
      ],
      "has_torrent": true,
      "has_active_torrent": true
    },
    {
      "path": "/mnt/data/Media/Movies/Movie.mkv",
      "torrents": [],
      "has_torrent": false,
      "has_active_torrent": false
    }
  ]
}
```

Two link counts are reported, and they are not the same thing:

- `link_count` — the number of paths (hardlinks) to this inode **found inside the scanned root**.
- `fs_link_count` — the inode's **true** hardlink count on the filesystem (`st_nlink`), counting every link on the device, including any outside the scanned root. When `fs_link_count` is `1`, the file has no other hardlinks anywhere; this is what allows a non-seeded file inside `--media-dir` to be treated as "used" (see [Media Directory Reclassification](#media-directory-reclassification)).

## Features

### Inode-Centric File Model

Every unique file is identified by its inode. Multiple paths to the same inode (hardlinks) are listed individually, each with its own torrent status. This is essential for torrent setups where one file is hardlinked into both a torrent directory and a media library.

Internally, files are keyed by a **collision-proof identity** rather than the inode number alone — `(device, inode)` on an ordinary filesystem, or `(branch, inode)` on a mergerfs union (see below). This matters because the whole tool trusts "same inode ⇒ same file" when deciding what's safe to delete, and on a union that assumption can otherwise be violated.

### mergerfs / union filesystems

If your storage is a [mergerfs](https://github.com/trapexit/mergerfs) union of several disks, **just point the tool at the union** (e.g. `/mnt/pool`) — it makes itself aware of the disks underneath and does the right thing:

- **Branch discovery + scanning the real disks.** On startup it reads the union's branch list (mergerfs' `user.mergerfs.branches`) and scans each underlying branch directly instead of the union. Scanning the real disks means inode identity, hardlink counts, and hardlink operations are all exact. The reports still land at the union path you gave.
- **No manual path config.** It auto-derives the branch→union path mappings qBittorrent needs (qBittorrent reports union paths; the scan sees branch paths), and expands any union `--media-dir` (e.g. `/mnt/pool/Media`) to its per-branch equivalents. You don't have to hand-write `--path-map` or list every branch's media folder.
- **Why this is safety-critical.** FUSE forces a single device id on the whole mount, and with `inodecalc=passthrough` mergerfs hands back the raw underlying inode. Two *different* files on two disks can then report the *same* `(device, inode)`. A naive inode tool would treat them as hardlinks of one file and, during cleanup, delete one "path" believing the data survives via the other — destroying it. This tool resolves each file's real branch (via `user.mergerfs.basepath`) and keys by `(branch, inode)`, so distinct files stay distinct. As an extra backstop, any inode whose in-scan path count exceeds its true `st_nlink` (impossible for a genuine hardlink group) is refused by every destructive phase. *(mergerfs' own default `inodecalc=hybrid-hash` also avoids the collision; the tool is safe under any setting.)*

Flags:
- `--no-mergerfs-expand` — scan the union tree literally instead of expanding to branches (still safe, via per-file branch resolution).
- `--mergerfs-branches "/mnt/a,/mnt/b"` — override auto-discovery (rarely needed).

Hardlinks can't cross mergerfs branches, so consolidating duplicates that live on *different* disks isn't a hardlink operation — see [Cross-Drive Duplicates](#cross-drive-duplicates).

### Scanning multiple locations

The path argument accepts **more than one** directory:

```bash
python3 disk.py /mnt/disk1 /mnt/disk2
```

Everything is scanned into one combined view, which is what lets the tool spot the same file living on two different drives. (Pointing at a mergerfs union does this for you by expanding to its branches.) Reports, log and cache are written next to `disk.py` (see [Output Files](#output-files)); the first path is recorded inside them as the scanned root.

### qBittorrent Integration

Connects to qBittorrent's Web API v2 to determine which files are part of active torrents. Works with self-signed HTTPS certificates (SSL verification disabled). Authentication uses session cookies.

**Multiple instances:** You can query more than one qBittorrent instance and the torrents from all of them are merged into a single pool — there is no differentiation by which instance a torrent came from. This is useful when you run separate instances (e.g. a local box and a seedbox) that seed content on the same drive. Instances come from any combination of:

- the single `--qbt-url` / `--qbt-user` / `--qbt-pass` (or `QBT_URL` / `QBT_USER` / `QBT_PASS` in `.env`),
- one or more `--qbt-instance "url|user|pass"` flags (repeatable; user and password are optional),
- the `QBT_INSTANCES` key in `.env` (see [Configuration](#configuration)).

Instances are de-duplicated by URL, so listing the same one twice is harmless. When the same torrent (identical infohash) is seeded on two instances, it is counted once; genuinely different torrents that happen to share a path are all kept. `--insecure` applies to every instance (a per-instance override is possible via the `insecure` key in a `QBT_INSTANCES` entry).

**Connection failure handling:** If any configured instance can't be reached, the script reports which ones failed and, in interactive mode, prompts you to continue (with the torrent data from the instances that *did* connect, or with none if all failed) or abort. In non-interactive mode (e.g. piped input or cron), it aborts automatically — a missing instance can make a seeded file look unused, which would be unsafe for the cleanup phases to act on.

**Path mapping (Docker / mergerfs):** qBittorrent often reports a torrent's files under a *different* path than the real filesystem — for example because it runs in a Docker container with bind mounts, or because it sees a mergerfs/union mount instead of the underlying branches. Without help, the script would compare its on-disk paths against qBittorrent's paths, find no match, and wrongly classify seeded files as **unused** (and potentially cross-seed them or flag their paths for removal).

Path mappings fix this. Each mapping translates an on-disk path prefix to the prefix qBittorrent reports. Suppose your files physically live under `/mnt/disk1` and `/mnt/disk2`, but qBittorrent (in its container) sees everything under `/mnt/pool`:

```bash
python3 disk.py /mnt/data \
    --qbt-url https://localhost:8080 --qbt-pass mypassword \
    --path-map "/mnt/disk1|/mnt/pool" \
    --path-map "/mnt/disk2|/mnt/pool"
```

Now a scanned file `/mnt/disk1/file.mkv` is looked up as `/mnt/pool/file.mkv`, matches the torrent qBittorrent is seeding, and is correctly classified as **used**. Notes:

- `--path-map` is repeatable, and several on-disk prefixes may map to the **same** qBittorrent prefix (as above).
- When prefixes overlap, the **longest** (most specific) matching prefix is used.
- The on-disk path is matched literally — a union/overlay prefix is not resolved to its underlying branch before mapping.
- Mappings can also be set via `PATH_MAPPINGS` in `.env` (see [Configuration](#configuration)); the `.env` value and the flags are merged.
- The original (unmapped) path is still checked too, so torrents that qBittorrent happens to report with the real path keep matching.

**Active vs. inactive torrents:** By default, only torrents in an active state count as "used" — this includes `uploading`, `stalledUP`, `downloading`, `stalledDL`, `checkingUP`, `checkingDL`, `queuedUP`, `queuedDL`, `forcedUP`, `forcedDL`, `moving`, `allocating`, `metaDL`, and `forcedMetaDL`. Paused and errored torrents are treated as inactive.

Use `--all-torrents` to treat every torrent as active regardless of state.

The terminal report uses symbols to distinguish status:

- `[T]` — path serves an **active** torrent
- `[P]` — path serves a **paused/inactive** torrent
- `[·]` — path has **no** torrent association

### Inode Classification

Each inode is classified based on its paths' torrent coverage:

| Category | Meaning |
|---|---|
| **Used** | All paths serve an active torrent |
| **Unused** | No paths serve any torrent |
| **Mixed** | Some paths have torrents, some don't |

### Media Directory Reclassification

The `--media-dir` option handles a common setup: a media library (e.g., for Plex/Jellyfin) living alongside your torrents. Files there often won't have direct torrent associations, which would otherwise classify them as "mixed" or "unused". With `--media-dir` set, two things are reclassified as **used**:

**1. Hardlinked-into-media (mixed → used).** When a file is hardlinked from a torrent directory into the media library, the torrent path seeds it and the media path serves it. Such a "mixed" inode is reclassified as "used" **if and only if** every non-torrent path is inside the media directory.

Key rules:
- Only affects **mixed** inodes (must have at least one torrent path)
- All non-torrent paths must be inside the media dir to reclassify

**2. Standalone media files (unused → used).** A file that lives **only** inside the media directory, has **no other hardlinks anywhere** (`fs_link_count` is 1), and isn't being seeded is treated as "used" rather than "unused". This is genuine, user-owned content — a personal rip, a manually-added file, etc. — that simply isn't attached to a torrent. Because it has no other hardlink, deleting it would lose the data, so it should not be flagged for cleanup or picked up by cross-seed.

Key rules:
- Only affects fully **unused** inodes inside the media dir
- Only when the file has no other hardlinks (`fs_link_count == 1`); an unused file that *is* hardlinked elsewhere (`fs_link_count > 1`) stays "unused"
- On by default; pass `--no-keep-unseeded-media` to disable it and classify these files as "unused" instead. (This flag does **not** affect case 1.)

Both behaviors require `--media-dir`. Without it, classification is unchanged.

`--media-dir` is **repeatable** — pass it once per location if your library spans several folders or several disks (e.g. `--media-dir /mnt/disk1/Media --media-dir /mnt/disk2/Media`). A path counts as "in the media library" if it's inside *any* of them. (When you point at a mergerfs union, a single union media path is expanded to each branch for you.)

### Two-Phase Duplicate Detection

Duplicates are files with identical content but different inodes — genuinely wasting disk space (unlike hardlinks, which share the same inode).

Detection uses a two-phase approach for speed:

1. **Partial hash** — hash the first + last 8 KB of files with matching sizes (fast filter to eliminate most non-duplicates)
2. **Full hash** — hash the entire content only for files that survived phase 1

**Drive-aware full-hash scheduling.** The full-hash phase is parallelised *per drive*, not by a flat thread count — because on a spinning disk, reading two files at once just makes the head seek back and forth and destroys throughput. So each **spinning** drive gets exactly **one** reader, while **different drives are read in parallel** (one reader each); as a drive runs out of work its reader exits, so concurrency falls automatically to a single reader once only one disk is left. This generalises to any number of drives (an N-HDD scan uses N readers). Drives detected as **SSD/NVMe** (non-rotational) aren't seek-bound and may use up to `--workers` readers each. `--workers` (default 4) is therefore the *per-SSD* cap; spinning disks ignore it and always use one reader. Set `--workers 1` to force fully sequential. Rotational vs. solid-state is detected from the OS (`/sys/.../queue/rotational`); if it can't be determined, the drive is treated as spinning (the safe choice — one reader never thrashes).

### Cross-Drive Duplicates

When you scan more than one drive (directly, or via a mergerfs union), the tool flags duplicate groups whose identical copies live on **different drives**. A hardlink can't span two filesystems, so the regular dedup phase can't touch these — and it no longer even prompts for them (a group whose copies are all on different drives is skipped in the dedup step, since "fixing" it would be a no-op). They're handled separately:

- Every cross-drive group is listed in the terminal and written to `cross_drive_duplicates.json` (each copy's drive + reclaimable space), and shown with a `⇄ CROSS-DRIVE` badge and a dedicated **Cross-Drive** tab in the HTML report. Reporting never changes anything on its own.
- To reclaim the space, pass `--consolidate-cross-drive`. This does **not** just delete a copy (that would make the union path vanish and could break a torrent). Instead it **migrates** the redundant copy onto the kept copy's drive: for each of its paths it recreates the file as a hardlink to the kept inode at the **same relative path** on the keeper's branch, then removes the original. On a mergerfs union the union path (e.g. `/mnt/pool/Data/x.mkv`) is unchanged — qBittorrent/Plex see no difference — and the redundant physical copy is freed. So a file with 7 hardlinks on disk A plus a copy on disk B becomes one inode with **8** hardlinks on A (the 8th at B's old relative path), and B's copy is gone.
- It always prompts per group (no `--auto`), suggests a keeper (seeded → in a media dir → most hardlinks), links **before** removing (the path is served throughout), never clobbers a different file already at the target, and respects `--dry-run`. If a scan isn't mergerfs (branches unknown), migration isn't possible and it falls back to deleting the redundant copy instead.
- The HTML **Cross-Drive** tab can build the same thing without the CLI: each group has a **"keep this → migration script"** button (and a **"Migration script (all, keep suggested)"** button) that downloads a `.sh` of `ln … && rm …` commands — the `&&` guard means a source is only removed if its new hardlink was created, so an existing target is never clobbered.

### Hash Cache (SQLite)

On a large drive, hashing is the bottleneck. The hash cache stores computed hashes in a SQLite database keyed by `(path, inode, size, mtime_ns)`. On re-runs, `stat()` (which is way faster than reading file contents) is used to check if a file has changed — if not, the cached hash is reused.

The cache uses WAL mode and per-thread connections for safe parallel access.

- Default location: `.disk_cache.db` next to `disk.py` (the script's own directory), so re-runs share one cache regardless of what you scan
- Override: `--hash-db /path/to/cache.db`
- Disable: `--no-cache`
- Force re-hash: `--rehash` (still updates the cache for next run)

Stale entries (files that no longer exist) are automatically pruned.

**Each hash is committed as soon as it's computed** (one small transaction per file), not batched at the end. So if a long hashing run is interrupted with `Ctrl+C` (or killed), every file already hashed is safely in the cache and won't be re-hashed next time — you only lose the file(s) actually being read at that instant (at most one per active reader). The next run picks up where it left off. This only applies with the cache enabled (the default); `--no-cache` saves nothing.

### Interactive Deduplication

When duplicates are found, the script can consolidate them into hardlinks using an atomic rename-hardlink-unlink pattern:

1. Rename the duplicate to a `.bak` file
2. Create a hardlink to the kept inode
3. Remove the `.bak` file

If the hardlink fails, the original is restored from `.bak`. If it works, every path that existed before still exists after — they just all point to the same inode now, freeing the duplicate blocks.

Modes:
- **Interactive** (default): prompts per duplicate group — `[y]es / [n]o / [a]ll remaining / [q]uit`
- **Auto-fix** (`--auto-fix`): fixes all without prompting
- **Dry run** (`--dry-run`): shows what would happen without touching files
- **Skip** (`--no-fix`): report only, no dedup

### Content Type Breakdown

Files are categorized by extension into media types: **video**, **audio**, **books**, **subtitle**, **image**, **metadata**, and **other**. Both the terminal report and HTML report show a breakdown of disk usage per type, and each JSON entry includes a `content_type` field.

### Age-Based Stale File Detection

Use `--stale-days N` to flag inodes that haven't been accessed in N days. The check uses `atime` (last access time), which is updated when a file is read — including when qBittorrent reads it for seeding. So a file being actively seeded won't be flagged as stale.

Each JSON entry gets a `stale: true/false` field, and the terminal report shows a stale file summary with counts and disk usage.

### Orphan Path Cleanup

For mixed inodes — files that are hardlinked into both a torrent directory and elsewhere — the script interactively removes "orphan" paths: paths that have no active torrent association **and** are not inside your `--media-dir`. This runs by default when `--media-dir` and a qBittorrent connection are available.

Since these are hardlinks, removing an orphan path only deletes the directory entry. The actual file data stays alive through the remaining paths (the torrent path that's seeding it, the media library path, etc.). No file content is ever lost.

Each inode is presented with all its paths clearly labelled:

- `[T]` — torrent path (kept)
- `[M]` — media dir path (kept)
- `[×]` — orphan path (candidate for removal)

Modes:
- **Interactive** (default): prompts per inode — `[y]es / [n]o / [a]ll remaining / [q]uit`
- **Auto-cleanup** (`--auto-cleanup`): removes all orphan paths without prompting
- **Dry run** (`--dry-run`): shows what would be removed without touching files
- **Skip** (`--no-cleanup-orphans`): skip orphan cleanup entirely

Safety: the script never removes a path if it would leave the inode with zero remaining paths.

### Empty Folder Cleanup

After orphan path removal and deduplication, directories can be left empty. The script finds directories whose **entire subtree is empty** (no files anywhere beneath them) and offers to remove each one — collapsing to the **topmost** such directory. So if `abc/xyz` contains 100 folders each holding 100 more, all empty, you get **one** prompt to remove `abc/xyz` (which takes the whole nested tree with it), not 10,001 prompts. Where a folder has a mix — say five empty subfolders plus one that holds a file — you get one prompt per empty subtree and the file-bearing one is kept.

This runs by default after all other cleanup phases. The scanned root directory itself is never removed. A directory containing a **symlink** is not considered empty (it's not removed, and the tool never deletes through a symlink), and a defensive re-check right before removal guarantees nothing with a file in it is ever deleted.

**mergerfs-aware (mirrored directory skeleton).** On a mergerfs union the directory tree is mirrored across every branch (`func.mkdir=epall`), and those empty mirror copies must stay put — mergerfs' create policies need the parent directory to already exist on a branch to place files there, so deleting a branch's copy of a folder can misdirect where future files land. Because of this, a folder is treated as empty **only when it is empty on every branch** (i.e. the union sees it empty). A folder that's empty on one disk but holds files on another is left alone. When a folder *is* empty everywhere, it's removed from all branches together, keeping the skeleton consistent. (This happens automatically when you point at a union or pass several drives; for a single ordinary directory it's just plain empty-dir cleanup.)

Modes:
- **Interactive** (default): prompts once per empty subtree — `[y]es / [n]o / [a]ll remaining / [q]uit`
- **Auto-cleanup** (`--auto-cleanup-empty`): removes all empty subtrees without prompting
- **Dry run** (`--dry-run`): shows what would be removed without touching directories
- **Skip** (`--no-cleanup-empty`): skip empty folder cleanup entirely

### mergerfs Skeleton Repair

On a mergerfs union the directory tree is supposed to be mirrored across every branch (`func.mkdir=epall` creates each new directory on all branches), so the create policies always have an "existing path" to target and files land where they should. If that ever slips — a directory exists under one branch's copy of the scanned subtree but not another's — this repairs it.

When you point at a union, then **after** empty-folder cleanup, the tool ensures every directory present under one branch also exists on the others, creating the missing ones (copying the source directory's mode/owner where possible). It's on by default and runs automatically; `--no-repair-skeleton` disables it and `--dry-run` shows what it would create.

It only ever **creates directories** — never files, never deletions — and running after empty cleanup means directories that were just removed as empty-everywhere aren't recreated. A path occupied by a *file* on one branch where another has a *directory* (a genuine union conflict) is reported and left untouched. It's idempotent, so re-running does nothing once the branches match. (Only applies when a union is expanded to its branches; with `--no-mergerfs-expand` it's skipped.)

### Extension Filtering

Use `--ignore-ext nfo,txt,srt,jpg` to skip files with those extensions during the scan. This keeps reports focused on content that matters for disk space rather than tiny metadata files.

You can set a default ignore list via `IGNORE_EXT` in `.env`. If `--ignore-ext` is passed as an argument, it fully replaces the `.env` list.

### Cross-Seed Directory

Pass `--cross-seed` to create a `cross-seed-dir/` directory in the scan root containing hardlinks to every file classified as "unused" (no active torrent on any of its paths). This is designed for use with cross-seed tools that need all candidate files in a single directory tree.

The relative path structure is preserved inside `cross-seed-dir/` so torrent content keeps its expected layout. Only hardlinks are created — no file data is copied, so this costs zero additional disk space. Re-running the command safely skips files that are already linked. Requires a qBittorrent connection for classification.

### Graceful Interruption

On a large drive, scans can take a long time. Pressing `Ctrl+C` triggers a graceful shutdown:

- If scan data has been collected, all JSON reports and the HTML report are written with partial results
- Hashing progress is **not** lost: the hash cache is committed per file as it goes (see [Hash Cache](#hash-cache-sqlite)), so a resumed run reuses everything already hashed
- A second `Ctrl+C` forces immediate exit
- Exit code is 130 (standard for SIGINT)

### Dual Output (Terminal + Log)

All terminal output is simultaneously written to `diskreport.log` (ANSI escape codes stripped). Use `--no-log` to disable.

## Configuration

Nothing is hardcoded in the script. All configuration lives in an adjacent **`.env`** file: copy `.env.example` to `.env` and edit it. The `.env` file is git-ignored so your paths and credentials are never committed.

```ini
# qBittorrent connection (leave blank to skip torrent classification)
QBT_URL=https://localhost:8080
QBT_USER=admin
QBT_PASS=yourpassword

# Extra qBittorrent instances, merged into one pool (JSON array of objects)
QBT_INSTANCES=[{"url":"https://seedbox:8080","user":"admin","pass":"","insecure":true}]

# Media library folder(s) — JSON array (handles spaces) or comma list.
# On a mergerfs union, list the media path on each branch.
MEDIA_DIRS=["/mnt/disk1/Media","/mnt/disk2/Media"]

# Map on-disk path prefixes to what qBittorrent reports (Docker/mergerfs).
# Auto-derived when you scan a union, so usually left as {}.
PATH_MAPPINGS={"/mnt/disk1":"/mnt/pool","/mnt/disk2":"/mnt/pool"}

# Extensions to skip during the scan (comma-separated, no dots)
IGNORE_EXT=nfo,txt,srt,jpg,png,nzb
```

Value resolution: a real **environment variable** of the same name wins, then the **`.env`** file, then the built-in default. So you can keep everything in `.env`, or override per-run, e.g. `QBT_PASS='secret' python3 disk.py /mnt/pool`. A command-line flag (`--qbt-url`, `--media-dir`, `--path-map`, …) overrides both. Point at a different config file with the `DISK_ENV` environment variable.

**On the password:** keep it in `.env` (git-ignored, stays on your machine) or pass it as an environment variable. Avoid `--qbt-pass` on the command line — arguments are visible in process listings (`ps aux`) and may land in shell history. (Advanced tuning keys — `ACTIVE_TORRENT_STATES`, `PARTIAL_BYTES`, `READ_CHUNK`, `REPORT_WIDTH` — are also accepted in `.env`; see `.env.example`. The media-type categories are defined in `MEDIA_TYPES` in the script.)

## All Options
```
positional arguments:
  PATH [PATH ...]       One or more directories to scan. Pass several (or a
                        mergerfs union, which expands to its branches) to detect
                        the same file across different drives. Reports/log/cache
                        go under the FIRST path.

options:
  --top N               Limit ranking lists to N entries (default: show all)
  --min-dup-mb N        Min file size in MB for dup detection (default: 1)
  --one-filesystem      Do not cross filesystem boundaries (DEFAULT: on; kept for
                        back-compat, now a no-op reaffirming the default)
  --cross-filesystem    Allow the scan to cross filesystem boundaries (turns the
                        default one-filesystem behavior off)
  --workers N           Max full-hash readers PER non-rotational (SSD/NVMe) drive
                        (default: 4). Spinning disks always use exactly 1 reader;
                        different drives are read in parallel. Set 1 for fully
                        sequential.
  -q, --quiet           Suppress progress output
  --no-log              Don't write diskreport.log
  --stale-days N        Flag inodes not accessed in N days as stale (0=off)
  --ignore-ext EXT,...  Comma-separated extensions to skip
  --media-dir DIR       Media folder for inode reclassification (mixed → used, and
                        non-seeded single-link files in this dir → used).
                        REPEATABLE — pass once per folder/branch
  --no-keep-unseeded-media  Classify non-seeded single-link files in --media-dir as
                        "unused" instead of "used" (default: keep them as "used")

mergerfs:
  --no-mergerfs-expand  Don't auto-expand a mergerfs union into its branches; scan
                        the union tree as-is (still collision-safe)
  --mergerfs-branches P1,P2,…   Override branch auto-discovery for a union root
  --no-repair-skeleton  Don't mirror the directory skeleton across branches after
                        empty-folder cleanup (default: on for expanded unions;
                        creates any dir present on one branch but missing on
                        another — directories only, never files/deletions)

qBittorrent:
  --qbt-url URL         Web UI base URL (else QBT_URL in .env)
  --qbt-user USER       Username (else QBT_USER in .env)
  --qbt-pass PASS       Password (prefer QBT_PASS in .env / env var over arg)
  --qbt-instance URL|USER|PASS   Add an EXTRA instance (repeatable); all instances'
                        torrents are merged into one pool (see QBT_INSTANCES constant)
  --path-map LOCAL|QBT  Map an on-disk path prefix to the prefix qBittorrent reports
                        (repeatable; for Docker bind mounts, mergerfs, etc.). E.g.
                        "/mnt/disk1|/mnt/pool". Merges with PATH_MAPPINGS in .env.
                        Auto-derived when you scan a mergerfs union
  --insecure            Disable SSL cert verification (self-signed certs); all instances
  --all-torrents        Treat ALL torrents as active (default: active only)

Hash cache:
  --hash-db FILE        SQLite cache location (default: REPORT_ROOT/.disk_cache.db)
  --no-cache            Disable the hash cache
  --rehash              Ignore cached hashes, re-hash everything

Deduplication:
  --no-fix              Skip interactive dedup (report only)
  --auto-fix            Fix all duplicates without prompting
  --dry-run             Show what dedup/cleanup would do without changing files
  --consolidate-cross-drive   Interactively reclaim files that exist on more than
                        one drive by migrating the redundant copy onto the kept
                        copy's drive (hardlink at the same relative path, then
                        remove the source; union path preserved). Always prompts;
                        no --auto

Orphan cleanup:
  --no-cleanup-orphans  Skip orphan path cleanup (on by default with --media-dir + qBt)
  --auto-cleanup        Remove all orphan paths without prompting

Empty folder cleanup:
  --no-cleanup-empty    Skip empty folder cleanup (on by default)
  --auto-cleanup-empty  Remove all empty folders without prompting

Cross-seed:
  --cross-seed          Hardlink unused files into ROOT/cross-seed-dir/ (requires qBt)
```

## Examples

### First audit of a large drive

```bash
python3 disk.py /mnt/data --no-fix --no-cleanup-orphans --no-cleanup-empty --stale-days 365
```

Scans everything, classifies all inodes, flags files untouched in a year, and writes reports without touching any files. Review the HTML report to understand what's on the drive.

### Routine maintenance with qBittorrent

```bash
python3 disk.py /mnt/data --media-dir /mnt/data/Media --ignore-ext nfo,txt,srt,jpg,png
```

With qBittorrent settings in `.env`, this scans the drive, classifies inodes against active torrents, treats the Media folder as expected for non-torrent paths, skips metadata files, and interactively offers to consolidate duplicates, remove orphan paths, and clean up empty folders.

### Multiple qBittorrent instances

```bash
python3 disk.py /mnt/data --media-dir /mnt/data/Media \
    --qbt-url https://localhost:8080 --qbt-pass localpw \
    --qbt-instance "https://seedbox:8080|admin|seedboxpw" \
    --qbt-instance "https://nas:8080|admin|naspw"
```

Pulls torrents from three instances (the `--qbt-url` one plus two `--qbt-instance` ones) and merges them into a single pool, so a file seeded by *any* of them counts as used. The same set of instances can instead be set via `QBT_INSTANCES` in `.env` to keep the command short.

### mergerfs pool: find duplicates within and across disks

```bash
python3 disk.py /mnt/pool --media-dir /mnt/pool/Media --no-fix --no-cleanup-orphans --no-cleanup-empty
```

Point at the union; the tool discovers the underlying disks, scans them directly, and derives the qBittorrent path mappings and per-branch media folders itself. Same-disk duplicates show up in `duplicate_files.json`; the same file appearing on two disks shows up in `cross_drive_duplicates.json`. Add `--consolidate-cross-drive` (drop the `--no-fix`) to interactively reclaim the cross-disk copies.

### Dry-run preview of all cleanups

```bash
python3 disk.py /mnt/data --dry-run --media-dir /mnt/data/Media
```

Shows what dedup consolidation, orphan path removal, and empty folder cleanup would do — without modifying anything.

### Full auto maintenance (no prompts)

```bash
python3 disk.py /mnt/data --media-dir /mnt/data/Media --auto-fix --auto-cleanup --auto-cleanup-empty
```

Runs all cleanup phases automatically without prompting. Use `--dry-run` first to preview.

### Quick top-level overview

```bash
python3 disk.py /mnt/data --top 20 --no-fix --no-cleanup-orphans --no-cleanup-empty -q
```

Shows the 20 largest files, 20 largest directories, and up to 20 duplicate groups. Quiet mode suppresses progress output. All cleanup phases are skipped — report only.

## Security

The script handles qBittorrent credentials and performs destructive file operations (dedup, orphan removal, empty dir cleanup). The following measures are in place:

* **Credential handling** — credentials live in the git-ignored `.env` file (or an environment variable), resolved as arg → env var → `.env`. Nothing is hardcoded in the script, so there are no credentials to accidentally commit.
* **SSL/TLS** — certificate verification is enabled by default. If your qBittorrent uses a self-signed cert, pass `--insecure` to bypass verification (this applies to every configured instance; a per-instance override is available via the `insecure` key in a `QBT_INSTANCES` entry). This disables MITM protection and should only be used on trusted networks, preferably localhost.
* **Deduplication safety** — the dedup engine uses an atomic rename→hardlink→unlink strategy with rollback on failure. Inode identity is verified after each rename to guard against TOCTOU race conditions. The `--dry-run` flag lets you preview all operations before committing.
* **SQL injection** — the SQLite hash cache uses parameterized queries throughout. No user input is interpolated into SQL strings.
* **HTML reports** — file paths are HTML-escaped before injection into the report template. The template uses fixed identifiers for JavaScript event handlers. This html report *will* contain your full filepaths.
* **Logging** — URLs are sanitized (credentials stripped) before being written to the log file or terminal. API error messages do not expose response bodies.
* **Union inode-collision safety** — on a mergerfs/FUSE union, two different files on different disks can report the same inode number. The tool defends against this by resolving each file's real branch and keying by `(branch, inode)`, plus refusing to act on any inode whose in-scan path count exceeds its true `st_nlink`. Without this, cleanup could delete a file believing a "duplicate path" kept it alive. See [mergerfs / union filesystems](#mergerfs--union-filesystems).
* **No data loss from hardlink ops** — dedup consolidation and orphan cleanup only ever remove a *directory entry* while another hardlink keeps the bytes alive; neither ever removes the last surviving path of an inode. The single exception is `--consolidate-cross-drive`, which by design deletes a real independent copy of a file — so it is opt-in, always prompts per group, has no auto mode, and honors `--dry-run`.

## Requirements

- **Python 3.9+** (uses `str | None` type hints)
- **Linux/macOS** (relies on `os.lstat`, `st_ino`, `os.link` for hardlink operations). The mergerfs branch-awareness and rotational (HDD/SSD) detection are Linux-only and degrade gracefully elsewhere (unions are scanned as-is; unknown drives are treated as spinning).
- **Optional:** `pip install xxhash` for ~3x faster hashing (falls back to SHA-256)
- **Optional:** qBittorrent with Web UI enabled for torrent classification

## How It Works

```
resolve scan root(s)
  if a root is a mergerfs union → discover branches, scan the real disks,
    auto-derive branch→union path mappings + per-branch media dirs
        │
        ▼
scan directory tree(s)  (one filesystem by default; merge multiple roots)
  key each file by a collision-proof identity: (device, inode) or (branch, inode)
        │
        ▼
collect inodes (size, paths, mtime, atime, fs link count, branch)
        │
        ▼
connect to qBittorrent (optional, one or more instances)
  fetch torrent file paths + states from each
  merge into a single pool (no source differentiation)
  (apply --path-map prefixes when matching on-disk paths)
        │
        ▼
two-phase duplicate detection
  phase 1: partial hash (head+tail 8KB)
  phase 2: full hash — one reader per spinning drive, parallel across drives,
           cached (each hash committed immediately → interruptible/resumable)
        │
        ▼
classify each inode: used / unused / mixed
  apply --all-torrents / active-only filter
  apply --media-dir reclassification:
    mixed → used (non-torrent paths only in media dir)
    unused → used (single-link non-seeded file in media dir;
                   off with --no-keep-unseeded-media)
        │
        ▼
interactive deduplication (same-drive)
  atomic rename → hardlink → unlink, with rollback on failure
  (cross-drive copies set aside — can't hardlink across disks)
        │
        ▼
cross-drive duplicates
  always report → cross_drive_duplicates.json
  optionally --consolidate-cross-drive: delete a redundant copy (prompts)
        │
        ▼
orphan path cleanup
  remove non-torrent paths outside media dir
  (hardlink data stays alive via remaining paths)
        │
        ▼
empty folder cleanup (mirror-aware, whole-subtree)
  one prompt per TOPMOST all-empty directory (removes its whole nested tree);
  on a union a subtree is empty only if it has no files on ANY branch, and it's
  removed from all branches together (keeps the mirrored skeleton intact)
        │
        ▼
mergerfs skeleton repair (union only, after empty cleanup)
  create any directory present on one branch but missing on another
  (dirs only — repairs func.mkdir=epall gaps; never files/deletions)
        │
        ▼
generate reports
  terminal output + log file
  JSON files (used, unused, mixed, duplicates, cross_drive_duplicates)
  interactive HTML report
```
