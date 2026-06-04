//! A tiny **in-memory filesystem** for the SentinelOS shell — a heap-backed tree
//! VFS the console drives through `ls`/`cat`/`mkdir`/`write`/`rm`/`cd`/`pwd`.
//!
//! This module carries the crate's `#![forbid(unsafe_code)]` and lives entirely
//! on the kernel heap (`alloc`): there is no block device, no persistence, and no
//! `core::fmt` — it is a pure data structure plus a small path resolver. State is
//! lost on reboot, which is exactly what we want for a demonstrable, dependency-
//! free filesystem.
//!
//! # Model
//!
//! A [`FileSystem`] owns a single tree of [`Node`]s rooted at `/`. A node is
//! either:
//! * a **directory** — an ordered map (a `Vec<(name, Node)>`) of child entries, or
//! * a **file** — an owned `Vec<u8>` of bytes (text is just UTF-8 bytes).
//!
//! The filesystem also tracks a **current working directory** as an absolute,
//! already-resolved component list (e.g. `["home"]` for `/home`). Every public
//! operation takes a user-typed path — absolute (`/foo/bar`) or relative
//! (`bar`, `..`, `.`) — resolves it against the CWD into a clean absolute
//! component list, then walks the tree.
//!
//! # Why a `Vec` map (not a `BTreeMap`)
//!
//! Directories are small (a handful of entries in this toy), insertion order is a
//! perfectly good listing order, and a `Vec<(String, Node)>` keeps the type free
//! of any `core::fmt`/ordering machinery — in keeping with the rest of the kernel,
//! which avoids `core::fmt` on this target. Lookups are linear but bounded.
//!
//! # Errors
//!
//! Every fallible call returns `Result<T, FsError>`; [`FsError`] has a stable
//! `message()` the shell prints verbatim. There are no panics on bad user input —
//! a missing file or a `cd` into a regular file is a normal [`FsError`].

use alloc::string::String;
use alloc::vec::Vec;

/// Why a filesystem operation failed. Each variant carries a short, fixed message
/// the shell can print directly (no `core::fmt`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsError {
    /// A path component did not exist.
    NotFound,
    /// An entry already exists where one was being created.
    AlreadyExists,
    /// Expected a directory but found a file (e.g. `cd readme.txt`).
    NotADirectory,
    /// Expected a file but found a directory (e.g. `cat /home`).
    IsADirectory,
    /// The path was empty or otherwise unusable (e.g. an empty file name).
    InvalidPath,
    /// Refused to remove the root directory `/`.
    CannotRemoveRoot,
}

impl FsError {
    /// A short, human-readable message for the shell to print verbatim.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            FsError::NotFound => "no such file or directory",
            FsError::AlreadyExists => "already exists",
            FsError::NotADirectory => "not a directory",
            FsError::IsADirectory => "is a directory",
            FsError::InvalidPath => "invalid path",
            FsError::CannotRemoveRoot => "cannot remove root",
        }
    }
}

/// One entry in the tree: either a directory (named children) or a file (bytes).
enum Node {
    /// A directory: insertion-ordered `(name, child)` pairs. Linear lookup, but
    /// directories are tiny in this toy filesystem.
    Dir(Vec<(String, Node)>),
    /// A regular file: owned bytes. Text content is just UTF-8 bytes.
    File(Vec<u8>),
}

impl Node {
    /// `true` if this node is a directory.
    const fn is_dir(&self) -> bool {
        matches!(self, Node::Dir(_))
    }

    /// Borrow the child map if this is a directory.
    fn children(&self) -> Option<&Vec<(String, Node)>> {
        match self {
            Node::Dir(kids) => Some(kids),
            Node::File(_) => None,
        }
    }

    /// Mutably borrow the child map if this is a directory.
    fn children_mut(&mut self) -> Option<&mut Vec<(String, Node)>> {
        match self {
            Node::Dir(kids) => Some(kids),
            Node::File(_) => None,
        }
    }
}

/// A single named entry in a directory listing, returned by [`FileSystem::list`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    /// The entry's name (no path, just the final component).
    pub name: String,
    /// `true` if the entry is a directory, `false` for a regular file.
    pub is_dir: bool,
}

/// The in-memory filesystem: a tree of [`Node`]s plus a current directory.
///
/// Construct with [`FileSystem::new`] (an empty root) or [`FileSystem::seeded`]
/// (a friendly starter tree). All paths passed to the public methods may be
/// absolute (`/a/b`) or relative to the CWD (`a/b`, `..`, `.`); they are resolved
/// before the tree is walked, so callers never need to pre-normalise.
pub struct FileSystem {
    /// The root directory node (always a [`Node::Dir`]).
    root: Node,
    /// The current working directory as a clean, absolute component list. The
    /// root is the empty list `[]` (rendered as `/`).
    cwd: Vec<String>,
}

impl FileSystem {
    /// Create an empty filesystem: just the root directory `/`, CWD at `/`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: Node::Dir(Vec::new()),
            cwd: Vec::new(),
        }
    }

    /// Create a filesystem pre-seeded with a small starter tree so `ls`/`cat`
    /// show something immediately after boot:
    ///
    /// ```text
    /// /
    /// ├── readme.txt   (a welcome message)
    /// └── home/
    ///     └── notes.txt
    /// ```
    #[must_use]
    pub fn seeded() -> Self {
        let mut fs = Self::new();
        // These cannot fail on a fresh tree, but we ignore the results defensively
        // rather than unwrap (no panics in the kernel for seed data).
        let _ = fs.write_file(
            "/readme.txt",
            b"Welcome to SentinelOS - a private OS built from scratch in Rust.\n\
              This filesystem lives entirely in RAM. Try: ls, cat, mkdir, write, rm, cd, pwd.\n",
        );
        let _ = fs.mkdir("/home");
        let _ = fs.write_file("/home/notes.txt", b"private - secure - yours\n");
        fs
    }

    /// The current working directory as an absolute path string (e.g. `/` or
    /// `/home`). Allocated fresh on each call.
    #[must_use]
    pub fn cwd(&self) -> String {
        components_to_path(&self.cwd)
    }

    /// Resolve a user-typed `path` against the CWD into a clean, absolute
    /// component list. Handles a leading `/` (absolute), `.` (current), `..`
    /// (parent, clamped at root), and skips empty components from doubled / or
    /// trailing slashes.
    fn resolve(&self, path: &str) -> Vec<String> {
        let mut out: Vec<String> = if path.starts_with('/') {
            Vec::new()
        } else {
            self.cwd.clone()
        };
        for part in path.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    out.pop();
                }
                name => out.push(String::from(name)),
            }
        }
        out
    }

    /// Walk to the node at an already-resolved `components` path, borrowing it.
    /// The empty list resolves to the root.
    fn node_at<'a>(&'a self, components: &[String]) -> Result<&'a Node, FsError> {
        let mut node = &self.root;
        for name in components {
            let kids = node.children().ok_or(FsError::NotADirectory)?;
            node = kids
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, child)| child)
                .ok_or(FsError::NotFound)?;
        }
        Ok(node)
    }

    /// Mutably walk to the node at an already-resolved `components` path.
    fn node_at_mut<'a>(&'a mut self, components: &[String]) -> Result<&'a mut Node, FsError> {
        let mut node = &mut self.root;
        for name in components {
            let kids = node.children_mut().ok_or(FsError::NotADirectory)?;
            node = kids
                .iter_mut()
                .find(|(n, _)| n == name)
                .map(|(_, child)| child)
                .ok_or(FsError::NotFound)?;
        }
        Ok(node)
    }

    /// List the directory at `path` (relative or absolute), sorted by insertion
    /// order. Listing a file is an [`FsError::NotADirectory`].
    pub fn list(&self, path: &str) -> Result<Vec<DirEntry>, FsError> {
        let comps = self.resolve(path);
        let node = self.node_at(&comps)?;
        let kids = node.children().ok_or(FsError::NotADirectory)?;
        let entries = kids
            .iter()
            .map(|(name, child)| DirEntry {
                name: name.clone(),
                is_dir: child.is_dir(),
            })
            .collect();
        Ok(entries)
    }

    /// Read the file at `path` as bytes. Reading a directory is an
    /// [`FsError::IsADirectory`].
    pub fn read_file(&self, path: &str) -> Result<&[u8], FsError> {
        let comps = self.resolve(path);
        let node = self.node_at(&comps)?;
        match node {
            Node::File(bytes) => Ok(bytes),
            Node::Dir(_) => Err(FsError::IsADirectory),
        }
    }

    /// Create the directory at `path`. The parent must already exist and be a
    /// directory; an existing entry of the same name is [`FsError::AlreadyExists`].
    pub fn mkdir(&mut self, path: &str) -> Result<(), FsError> {
        let comps = self.resolve(path);
        let (parent, name) = split_parent(&comps)?;
        let parent_node = self.node_at_mut(parent)?;
        let kids = parent_node.children_mut().ok_or(FsError::NotADirectory)?;
        if kids.iter().any(|(n, _)| n == name) {
            return Err(FsError::AlreadyExists);
        }
        kids.push((String::from(name), Node::Dir(Vec::new())));
        Ok(())
    }

    /// Create or overwrite the file at `path` with `content`. The parent must
    /// exist and be a directory; if a directory already sits at `path` the call
    /// fails with [`FsError::IsADirectory`].
    pub fn write_file(&mut self, path: &str, content: &[u8]) -> Result<(), FsError> {
        let comps = self.resolve(path);
        let (parent, name) = split_parent(&comps)?;
        let parent_node = self.node_at_mut(parent)?;
        let kids = parent_node.children_mut().ok_or(FsError::NotADirectory)?;
        if let Some((_, existing)) = kids.iter_mut().find(|(n, _)| n == name) {
            match existing {
                Node::File(bytes) => {
                    bytes.clear();
                    bytes.extend_from_slice(content);
                    Ok(())
                }
                Node::Dir(_) => Err(FsError::IsADirectory),
            }
        } else {
            kids.push((String::from(name), Node::File(content.to_vec())));
            Ok(())
        }
    }

    /// Remove the entry (file or directory, recursively) at `path`. Removing the
    /// root `/` is refused with [`FsError::CannotRemoveRoot`].
    pub fn remove(&mut self, path: &str) -> Result<(), FsError> {
        let comps = self.resolve(path);
        let (parent, name) = split_parent(&comps).map_err(|e| match e {
            // An empty resolved path means the target was the root itself.
            FsError::InvalidPath => FsError::CannotRemoveRoot,
            other => other,
        })?;
        let parent_node = self.node_at_mut(parent)?;
        let kids = parent_node.children_mut().ok_or(FsError::NotADirectory)?;
        let idx = kids
            .iter()
            .position(|(n, _)| n == name)
            .ok_or(FsError::NotFound)?;
        kids.remove(idx);
        Ok(())
    }

    /// Change the current working directory to `path`. The target must exist and
    /// be a directory. On success the CWD is updated to the resolved absolute
    /// path; on failure the CWD is unchanged.
    pub fn change_dir(&mut self, path: &str) -> Result<(), FsError> {
        let comps = self.resolve(path);
        let node = self.node_at(&comps)?;
        if !node.is_dir() {
            return Err(FsError::NotADirectory);
        }
        self.cwd = comps;
        Ok(())
    }
}

impl Default for FileSystem {
    fn default() -> Self {
        Self::new()
    }
}

/// Render an absolute component list as a path string: `[]` → `/`,
/// `["home"]` → `/home`, `["a", "b"]` → `/a/b`.
fn components_to_path(components: &[String]) -> String {
    if components.is_empty() {
        return String::from("/");
    }
    let mut s = String::new();
    for part in components {
        s.push('/');
        s.push_str(part);
    }
    s
}

/// Split a resolved absolute component list into `(parent_components, final_name)`.
/// An empty list (the root) has no parent/name and is an [`FsError::InvalidPath`].
fn split_parent(components: &[String]) -> Result<(&[String], &str), FsError> {
    match components.split_last() {
        Some((name, parent)) => Ok((parent, name.as_str())),
        None => Err(FsError::InvalidPath),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh filesystem is an empty root with CWD at `/`.
    #[test]
    fn new_fs_is_empty_root() {
        let fs = FileSystem::new();
        assert_eq!(fs.cwd(), "/");
        assert!(fs.list("/").unwrap().is_empty());
    }

    /// The seeded tree exposes `/readme.txt` and `/home` immediately.
    #[test]
    fn seeded_fs_has_readme_and_home() {
        let fs = FileSystem::seeded();
        let root: Vec<String> = fs.list("/").unwrap().into_iter().map(|e| e.name).collect();
        assert!(root.contains(&String::from("readme.txt")));
        assert!(root.contains(&String::from("home")));
        let readme = fs.read_file("/readme.txt").unwrap();
        assert!(core::str::from_utf8(readme)
            .unwrap()
            .contains("Welcome to SentinelOS"));
        // /home is itself a directory holding notes.txt.
        let home: Vec<String> = fs
            .list("/home")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(home, [String::from("notes.txt")]);
    }

    /// `mkdir` then `list` shows the new directory, flagged as a directory.
    #[test]
    fn mkdir_then_list() {
        let mut fs = FileSystem::new();
        fs.mkdir("/foo").unwrap();
        let entries = fs.list("/").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "foo");
        assert!(entries[0].is_dir);
    }

    /// `mkdir` of an existing name fails with `AlreadyExists`.
    #[test]
    fn mkdir_duplicate_is_already_exists() {
        let mut fs = FileSystem::new();
        fs.mkdir("/foo").unwrap();
        assert_eq!(fs.mkdir("/foo"), Err(FsError::AlreadyExists));
    }

    /// `mkdir` under a missing parent fails with `NotFound`.
    #[test]
    fn mkdir_missing_parent_is_not_found() {
        let mut fs = FileSystem::new();
        assert_eq!(fs.mkdir("/nope/child"), Err(FsError::NotFound));
    }

    /// Writing then reading a file round-trips the bytes.
    #[test]
    fn write_then_read_roundtrips() {
        let mut fs = FileSystem::new();
        fs.write_file("/a.txt", b"hello").unwrap();
        assert_eq!(fs.read_file("/a.txt").unwrap(), b"hello");
    }

    /// Writing the same path twice overwrites the content.
    #[test]
    fn write_overwrites_existing_file() {
        let mut fs = FileSystem::new();
        fs.write_file("/a.txt", b"first").unwrap();
        fs.write_file("/a.txt", b"second").unwrap();
        assert_eq!(fs.read_file("/a.txt").unwrap(), b"second");
    }

    /// Reading a directory yields `IsADirectory`; `cat`-ing a missing file yields
    /// `NotFound`.
    #[test]
    fn read_errors_are_typed() {
        let mut fs = FileSystem::new();
        fs.mkdir("/d").unwrap();
        assert_eq!(fs.read_file("/d"), Err(FsError::IsADirectory));
        assert_eq!(fs.read_file("/missing"), Err(FsError::NotFound));
    }

    /// Writing over a directory path fails with `IsADirectory`.
    #[test]
    fn write_over_dir_is_is_a_directory() {
        let mut fs = FileSystem::new();
        fs.mkdir("/d").unwrap();
        assert_eq!(fs.write_file("/d", b"x"), Err(FsError::IsADirectory));
    }

    /// `remove` deletes a file; a second remove reports `NotFound`.
    #[test]
    fn remove_deletes_entry() {
        let mut fs = FileSystem::new();
        fs.write_file("/a.txt", b"x").unwrap();
        fs.remove("/a.txt").unwrap();
        assert_eq!(fs.read_file("/a.txt"), Err(FsError::NotFound));
        assert_eq!(fs.remove("/a.txt"), Err(FsError::NotFound));
    }

    /// `remove` of a non-empty directory deletes the whole subtree.
    #[test]
    fn remove_dir_is_recursive() {
        let mut fs = FileSystem::new();
        fs.mkdir("/d").unwrap();
        fs.write_file("/d/inner.txt", b"x").unwrap();
        fs.remove("/d").unwrap();
        assert!(fs.list("/").unwrap().is_empty());
    }

    /// Removing the root is refused.
    #[test]
    fn remove_root_is_refused() {
        let mut fs = FileSystem::new();
        assert_eq!(fs.remove("/"), Err(FsError::CannotRemoveRoot));
    }

    /// `cd` into a directory updates the CWD; relative paths resolve against it.
    #[test]
    fn cd_updates_cwd_and_relative_paths_resolve() {
        let mut fs = FileSystem::new();
        fs.mkdir("/home").unwrap();
        fs.change_dir("/home").unwrap();
        assert_eq!(fs.cwd(), "/home");
        // A relative write lands inside /home.
        fs.write_file("note.txt", b"hi").unwrap();
        assert_eq!(fs.read_file("/home/note.txt").unwrap(), b"hi");
        // And a relative list shows it.
        let names: Vec<String> = fs.list(".").unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(names, [String::from("note.txt")]);
    }

    /// `cd ..` walks toward the root and clamps there.
    #[test]
    fn cd_dotdot_walks_to_parent_and_clamps_at_root() {
        let mut fs = FileSystem::new();
        fs.mkdir("/a").unwrap();
        fs.mkdir("/a/b").unwrap();
        fs.change_dir("/a/b").unwrap();
        assert_eq!(fs.cwd(), "/a/b");
        fs.change_dir("..").unwrap();
        assert_eq!(fs.cwd(), "/a");
        // Two more `..` from /a can't go above root.
        fs.change_dir("..").unwrap();
        fs.change_dir("..").unwrap();
        assert_eq!(fs.cwd(), "/");
    }

    /// `cd` into a file is rejected and leaves the CWD unchanged.
    #[test]
    fn cd_into_file_is_rejected() {
        let mut fs = FileSystem::new();
        fs.write_file("/a.txt", b"x").unwrap();
        assert_eq!(fs.change_dir("/a.txt"), Err(FsError::NotADirectory));
        assert_eq!(fs.cwd(), "/");
    }

    /// Doubled and trailing slashes resolve the same as the clean path.
    #[test]
    fn messy_slashes_resolve_cleanly() {
        let mut fs = FileSystem::new();
        fs.mkdir("/a").unwrap();
        fs.write_file("//a///b.txt", b"x").unwrap();
        assert_eq!(fs.read_file("/a/b.txt").unwrap(), b"x");
    }

    /// Every `FsError` exposes a non-empty message.
    #[test]
    fn errors_have_messages() {
        for err in [
            FsError::NotFound,
            FsError::AlreadyExists,
            FsError::NotADirectory,
            FsError::IsADirectory,
            FsError::InvalidPath,
            FsError::CannotRemoveRoot,
        ] {
            assert!(!err.message().is_empty());
        }
    }
}
