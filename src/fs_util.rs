use std::io::Write;
use std::path::Path;

/// Atomically write `contents` to `path` by writing to a temp sibling file,
/// fsync'ing it, then renaming over the destination. The temp file name is
/// suffixed with the current process id so concurrent writers don't collide.
///
/// On POSIX, `rename(2)` is atomic when source and destination live on the
/// same filesystem, which is the case here because we always write the temp
/// file in the destination's parent directory.
pub fn atomic_write(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unnamed".into());
    let tmp = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));

    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }

    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Best-effort cleanup of the temp file if the rename failed.
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}
