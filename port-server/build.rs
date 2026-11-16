use std::{
    collections::{BTreeMap, HashSet},
    env, fs, io,
    path::{Path, PathBuf},
};

struct AssetEntry {
    raw: PathBuf,
    gzip: Option<PathBuf>,
}

struct Woff2Index {
    exact: HashSet<(String, String)>,
    vite_base: HashSet<(String, String)>,
}

impl Woff2Index {
    fn from_files(files: &[(String, PathBuf)]) -> Self {
        let mut exact = HashSet::new();
        let mut vite_base = HashSet::new();
        for (name, _) in files {
            let (dir, stem, ext) = split_dir_stem_ext(name);
            if ext.eq_ignore_ascii_case("woff2") {
                exact.insert((dir.to_string(), stem.to_string()));
                if let Some(base) = strip_vite_hash(stem) {
                    vite_base.insert((dir.to_string(), base.to_string()));
                }
            }
        }
        Self { exact, vite_base }
    }

    fn has_woff2_sibling(&self, dir: &str, stem: &str) -> bool {
        if self.exact.contains(&(dir.to_string(), stem.to_string())) {
            return true;
        }
        strip_vite_hash(stem)
            .is_some_and(|base| self.vite_base.contains(&(dir.to_string(), base.to_string())))
    }
}

fn split_dir_stem_ext(name: &str) -> (&str, &str, &str) {
    let (dir, file) = name.rsplit_once('/').unwrap_or(("", name));
    let (stem, ext) = file.rsplit_once('.').unwrap_or((file, ""));
    (dir, stem, ext)
}

/// Strips a standard 8-character Rollup/Vite asset hash suffix (`-<8 base64url chars>`).
fn strip_vite_hash(stem: &str) -> Option<&str> {
    let bytes = stem.as_bytes();
    if bytes.len() <= 9 {
        return None;
    }
    let split = bytes.len() - 9;
    if bytes[split] != b'-' {
        return None;
    }
    let hash = &bytes[split + 1..];
    if hash
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
    {
        Some(&stem[..split])
    } else {
        None
    }
}

fn should_skip_asset(name: &str, woff2_index: &Woff2Index) -> bool {
    let (dir, stem, ext) = split_dir_stem_ext(name);
    if ext.eq_ignore_ascii_case("map") {
        return true;
    }
    (ext.eq_ignore_ascii_case("ttf") || ext.eq_ignore_ascii_case("woff"))
        && woff2_index.has_woff2_sibling(dir, stem)
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) -> io::Result<()> {
    let mut entries = fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let kind = entry.file_type()?;
        let path = entry.path();
        if kind.is_symlink() {
            return Err(io::Error::other("asset symlinks are not supported"));
        }
        if kind.is_dir() {
            println!("cargo:rerun-if-changed={}", path.display());
            collect(root, &path, out)?;
        } else if kind.is_file() {
            println!("cargo:rerun-if-changed={}", path.display());
            let relative = path.strip_prefix(root).map_err(io::Error::other)?;
            let name = relative
                .components()
                .map(|c| {
                    c.as_os_str()
                        .to_str()
                        .ok_or_else(|| io::Error::other("asset name is not UTF-8"))
                })
                .collect::<Result<Vec<_>, _>>()?
                .join("/");
            out.push((name, path));
        }
    }
    Ok(())
}

fn build_asset_map(files: Vec<(String, PathBuf)>) -> BTreeMap<String, AssetEntry> {
    let woff2_index = Woff2Index::from_files(&files);
    let mut entries = BTreeMap::new();
    let mut gz_candidates = Vec::new();

    for (name, path) in files {
        if let Some(base) = name.strip_suffix(".gz") {
            let base = base.to_string();
            gz_candidates.push((name, base, path));
        } else if !should_skip_asset(&name, &woff2_index) {
            entries.insert(
                name,
                AssetEntry {
                    raw: path,
                    gzip: None,
                },
            );
        }
    }

    for (name, base, path) in gz_candidates {
        if let Some(entry) = entries.get_mut(&base) {
            entry.gzip = Some(path);
        } else if !should_skip_asset(&base, &woff2_index) {
            entries.insert(
                name,
                AssetEntry {
                    raw: path,
                    gzip: None,
                },
            );
        }
    }

    entries
}

fn main() -> io::Result<()> {
    println!("cargo:rerun-if-env-changed=OPENBOT_ASSETS_DIR");
    if env::var_os("CARGO_FEATURE_EMBEDDED_WWW").is_none() {
        return Ok(());
    }
    let root = env::var_os("OPENBOT_ASSETS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("../app/dist")
        });
    let root = fs::canonicalize(root)?;
    println!("cargo:rerun-if-changed={}", root.display());
    let mut files = Vec::new();
    collect(&root, &root, &mut files)?;
    let entries = build_asset_map(files);
    if !entries.contains_key("index.html") {
        return Err(io::Error::other("website build is missing index.html"));
    }

    let mut code = String::from(
        "pub type EmbeddedAsset = (&'static [u8], Option<&'static [u8]>);\n\
         #[allow(dead_code)]\n\
         pub fn asset_with_gzip(path: &str) -> Option<EmbeddedAsset> { match path {\n",
    );
    for (name, entry) in entries {
        let raw_file = entry
            .raw
            .to_str()
            .ok_or_else(|| io::Error::other("asset path is not UTF-8"))?;
        match entry.gzip {
            Some(gz_path) => {
                let gz_file = gz_path
                    .to_str()
                    .ok_or_else(|| io::Error::other("gzip asset path is not UTF-8"))?;
                code.push_str(&format!(
                    "{:?} => Some((include_bytes!({:?}), Some(include_bytes!({:?})))),\n",
                    name, raw_file, gz_file
                ));
            }
            None => {
                code.push_str(&format!(
                    "{:?} => Some((include_bytes!({:?}), None)),\n",
                    name, raw_file
                ));
            }
        }
    }
    code.push_str(
        "_ => None, } }\n\
         #[allow(dead_code)]\n\
         pub fn asset(path: &str) -> Option<&'static [u8]> {\n\
             asset_with_gzip(path).map(|(bytes, _)| bytes)\n\
         }\n",
    );
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("embedded_assets.rs"),
        code,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_maps_and_redundant_fonts_while_keeping_unmatched_and_pairing_gz() {
        let files = vec![
            ("index.html".into(), PathBuf::from("index.html")),
            ("assets/app-Ab12Cd34.js".into(), PathBuf::from("app.js")),
            ("assets/app-Ab12Cd34.js.gz".into(), PathBuf::from("app.js.gz")),
            ("assets/app-Ab12Cd34.js.map".into(), PathBuf::from("app.js.map")),
            ("assets/app-Ab12Cd34.js.map.gz".into(), PathBuf::from("app.js.map.gz")),
            (
                "assets/KaTeX_AMS-Regular-BQhdFMY1.woff2".into(),
                PathBuf::from("katex.woff2"),
            ),
            (
                "assets/KaTeX_AMS-Regular-DMm9YOAa.woff".into(),
                PathBuf::from("katex.woff"),
            ),
            (
                "assets/KaTeX_AMS-Regular-DRggAlZN.ttf".into(),
                PathBuf::from("katex.ttf"),
            ),
            (
                "assets/KaTeX_AMS-Regular-DMm9YOAa.woff.gz".into(),
                PathBuf::from("katex.woff.gz"),
            ),
            (
                "assets/KaTeX_Size3-Regular-CTq5MqoE.woff".into(),
                PathBuf::from("size3.woff"),
            ),
            ("fonts/custom.woff2".into(), PathBuf::from("custom.woff2")),
            ("fonts/custom.ttf".into(), PathBuf::from("custom.ttf")),
        ];
        let map = build_asset_map(files);
        assert!(map.contains_key("index.html"));
        assert!(map["assets/app-Ab12Cd34.js"].gzip.is_some());
        assert!(!map.contains_key("assets/app-Ab12Cd34.js.gz"));
        assert!(!map.contains_key("assets/app-Ab12Cd34.js.map"));
        assert!(!map.contains_key("assets/app-Ab12Cd34.js.map.gz"));
        assert!(map.contains_key("assets/KaTeX_AMS-Regular-BQhdFMY1.woff2"));
        assert!(!map.contains_key("assets/KaTeX_AMS-Regular-DMm9YOAa.woff"));
        assert!(!map.contains_key("assets/KaTeX_AMS-Regular-DRggAlZN.ttf"));
        assert!(!map.contains_key("assets/KaTeX_AMS-Regular-DMm9YOAa.woff.gz"));
        assert!(map.contains_key("assets/KaTeX_Size3-Regular-CTq5MqoE.woff"));
        assert!(map.contains_key("fonts/custom.woff2"));
        assert!(!map.contains_key("fonts/custom.ttf"));
    }
}
