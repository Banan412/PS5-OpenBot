use axum::{
    body::Body,
    http::{header, HeaderMap, HeaderValue},
    response::Response,
};
use std::{
    collections::HashSet,
    ffi::OsString,
    path::{Path, PathBuf},
};
use tokio_util::io::ReaderStream;

const IMMUTABLE_CACHE: &str = "public, max-age=31536000, immutable";
const NO_CACHE: &str = "no-cache";

/// Returns `true` when the request advertises `gzip` with a non-zero quality factor.
pub fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|item| {
            let mut parts = item.split(';').map(str::trim);
            let Some(coding) = parts.next() else {
                return false;
            };
            if !coding.eq_ignore_ascii_case("gzip") {
                return false;
            }
            for param in parts {
                if let Some((key, raw_q)) = param.split_once('=') {
                    if key.trim().eq_ignore_ascii_case("q") {
                        return raw_q
                            .trim()
                            .parse::<f32>()
                            .is_ok_and(|q| q > 0.0);
                    }
                }
            }
            true
        })
}

/// Returns `Cache-Control` for a static asset path: immutable for `/assets/...` bundles,
/// `no-cache` for `index.html` and unhashed top-level files.
pub fn cache_control_for(relative: &Path) -> HeaderValue {
    let normalized = normalize_relative(relative);
    if is_immutable_bundle(&normalized) {
        HeaderValue::from_static(IMMUTABLE_CACHE)
    } else {
        HeaderValue::from_static(NO_CACHE)
    }
}

/// Builds an HTTP response from an embedded asset lookup `(raw_bytes, optional_gzip_bytes)`.
#[allow(dead_code)]
pub fn response_for_embedded<F>(
    relative: &Path,
    is_head: bool,
    accepts_gzip: bool,
    asset_lookup: F,
) -> Option<Response>
where
    F: FnOnce(&str) -> Option<(&'static [u8], Option<&'static [u8]>)>,
{
    let name = normalize_relative_utf8(relative)?;
    if name.is_empty() {
        return None;
    }
    let (raw, gzip) = asset_lookup(&name)?;
    let (bytes, is_gzip) = match (accepts_gzip, gzip) {
        (true, Some(gz)) => (gz, true),
        _ => (raw, false),
    };
    let body = if is_head {
        Body::empty()
    } else {
        Body::from(bytes)
    };
    build_response(
        body,
        Path::new(&name),
        bytes.len() as u64,
        relative,
        gzip.is_some(),
        is_gzip,
    )
}

/// Streams a filesystem static asset under `root`, negotiating a `<path>.gz` sidecar when allowed.
#[allow(dead_code)]
pub async fn response_for_file(
    root: &Path,
    relative: &Path,
    is_head: bool,
    accepts_gzip: bool,
) -> Option<Response> {
    let path = tokio::fs::canonicalize(root.join(relative)).await.ok()?;
    if !path.starts_with(root) {
        return None;
    }
    let metadata = tokio::fs::metadata(&path).await.ok()?;
    if !metadata.is_file() {
        return None;
    }

    let gz_sidecar = find_gz_sidecar(root, &path).await;
    let (serve_path, serve_len, is_gzip) = match (accepts_gzip, &gz_sidecar) {
        (true, Some((gz_path, gz_len))) => (gz_path.as_path(), *gz_len, true),
        _ => (path.as_path(), metadata.len(), false),
    };

    let body = if is_head {
        Body::empty()
    } else {
        let file = tokio::fs::File::open(serve_path).await.ok()?;
        Body::from_stream(ReaderStream::new(file))
    };

    build_response(
        body,
        &path,
        serve_len,
        relative,
        gz_sidecar.is_some(),
        is_gzip,
    )
}

async fn find_gz_sidecar(root: &Path, raw_path: &Path) -> Option<(PathBuf, u64)> {
    if raw_path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("gz"))
    {
        return None;
    }
    let mut gz_os: OsString = raw_path.as_os_str().to_os_string();
    gz_os.push(".gz");
    let gz_path = tokio::fs::canonicalize(PathBuf::from(gz_os)).await.ok()?;
    if !gz_path.starts_with(root) {
        return None;
    }
    let gz_meta = tokio::fs::metadata(&gz_path).await.ok()?;
    gz_meta.is_file().then_some((gz_path, gz_meta.len()))
}

fn build_response(
    body: Body,
    content_type_path: &Path,
    content_length: u64,
    relative: &Path,
    has_gzip_variant: bool,
    is_gzip: bool,
) -> Option<Response> {
    let mime = mime_guess::from_path(content_type_path).first_or_octet_stream();
    let mut response = Response::new(body);
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(mime.as_ref()).ok()?,
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&content_length.to_string()).ok()?,
    );
    headers.insert(header::CACHE_CONTROL, cache_control_for(relative));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    if has_gzip_variant {
        headers.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    }
    if is_gzip {
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    }
    Some(response)
}

fn normalize_relative(relative: &Path) -> String {
    relative
        .to_string_lossy()
        .replace('\\', "/")
        .trim_start_matches('/')
        .to_string()
}

fn normalize_relative_utf8(relative: &Path) -> Option<String> {
    Some(
        relative
            .to_str()?
            .replace('\\', "/")
            .trim_start_matches('/')
            .to_string(),
    )
}

fn is_immutable_bundle(normalized: &str) -> bool {
    normalized.starts_with("assets/") && !normalized.ends_with(".html")
}

/// Pure asset-filtering helper mirroring `build.rs` rules for embedded bundles.
#[allow(dead_code)]
pub fn filter_embedded_paths<'a>(paths: &[&'a str]) -> Vec<&'a str> {
    let mut woff2_exact = HashSet::new();
    let mut woff2_vite = HashSet::new();
    for &name in paths {
        let (dir, stem, ext) = split_dir_stem_ext(name);
        if ext.eq_ignore_ascii_case("woff2") {
            woff2_exact.insert((dir, stem));
            if let Some(base) = strip_vite_hash(stem) {
                woff2_vite.insert((dir, base));
            }
        }
    }

    let is_skipped = |name: &str| {
        let (dir, stem, ext) = split_dir_stem_ext(name);
        if ext.eq_ignore_ascii_case("map") {
            return true;
        }
        (ext.eq_ignore_ascii_case("ttf") || ext.eq_ignore_ascii_case("woff"))
            && (woff2_exact.contains(&(dir, stem))
                || strip_vite_hash(stem).is_some_and(|base| woff2_vite.contains(&(dir, base))))
    };

    let kept_raw: HashSet<&str> = paths
        .iter()
        .copied()
        .filter(|name| !name.ends_with(".gz") && !is_skipped(name))
        .collect();

    paths
        .iter()
        .copied()
        .filter(|name| {
            if let Some(base) = name.strip_suffix(".gz") {
                !kept_raw.contains(base) && !is_skipped(base)
            } else {
                !is_skipped(name)
            }
        })
        .collect()
}

fn split_dir_stem_ext(name: &str) -> (&str, &str, &str) {
    let (dir, file) = name.rsplit_once('/').unwrap_or(("", name));
    let (stem, ext) = file.rsplit_once('.').unwrap_or((file, ""));
    (dir, stem, ext)
}

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
    hash.iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
        .then_some(&stem[..split])
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[test]
    fn skips_sourcemaps_and_redundant_fonts_in_favor_of_woff2() {
        let input = [
            "index.html",
            "assets/index-Clv8J_mq.js",
            "assets/index-Clv8J_mq.js.gz",
            "assets/index-Clv8J_mq.js.map",
            "assets/index-Clv8J_mq.js.map.gz",
            "assets/KaTeX_AMS-Regular-BQhdFMY1.woff2",
            "assets/KaTeX_AMS-Regular-DMm9YOAa.woff",
            "assets/KaTeX_AMS-Regular-DRggAlZN.ttf",
            "assets/KaTeX_Size3-Regular-CTq5MqoE.woff",
            "assets/font-unhashed.woff2",
            "assets/font-unhashed.ttf",
            "assets/font-unhashed.woff",
        ];
        let kept = filter_embedded_paths(&input);
        assert_eq!(
            kept,
            vec![
                "index.html",
                "assets/index-Clv8J_mq.js",
                "assets/KaTeX_AMS-Regular-BQhdFMY1.woff2",
                "assets/KaTeX_Size3-Regular-CTq5MqoE.woff",
                "assets/font-unhashed.woff2",
            ]
        );
    }

    #[test]
    fn cache_control_distinguishes_immutable_bundles_from_top_level_files() {
        assert_eq!(
            cache_control_for(Path::new("assets/index-Clv8J_mq.js")),
            IMMUTABLE_CACHE
        );
        assert_eq!(
            cache_control_for(Path::new("/assets/katex-BYZTj3zW.css")),
            IMMUTABLE_CACHE
        );
        assert_eq!(cache_control_for(Path::new("index.html")), NO_CACHE);
        assert_eq!(cache_control_for(Path::new("favicon.svg")), NO_CACHE);
        assert_eq!(cache_control_for(Path::new("/robots.txt")), NO_CACHE);
    }

    #[test]
    fn gzip_header_negotiation_respects_quality_values() {
        let mut headers = HeaderMap::new();
        assert!(!accepts_gzip(&headers));

        headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("br, deflate"));
        assert!(!accepts_gzip(&headers));

        headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip;q=0"));
        assert!(!accepts_gzip(&headers));

        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("br, gzip;q=0.8"),
        );
        assert!(accepts_gzip(&headers));

        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        assert!(accepts_gzip(&headers));
    }

    #[tokio::test]
    async fn embedded_response_negotiates_gzip_and_preserves_raw_fallback() {
        let lookup = |name: &str| match name {
            "assets/app-Ab12Cd34.js" => Some((b"console.log(1);".as_slice(), Some(b"GZBYTES".as_slice()))),
            "index.html" => Some((b"<html>ok</html>".as_slice(), None)),
            _ => None,
        };

        let gz_resp =
            response_for_embedded(Path::new("assets/app-Ab12Cd34.js"), false, true, lookup)
                .unwrap();
        assert_eq!(gz_resp.headers()[header::CONTENT_ENCODING], "gzip");
        assert_eq!(gz_resp.headers()[header::VARY], "Accept-Encoding");
        assert_eq!(gz_resp.headers()["x-content-type-options"], "nosniff");
        assert_eq!(gz_resp.headers()[header::CACHE_CONTROL], IMMUTABLE_CACHE);
        assert_eq!(gz_resp.headers()[header::CONTENT_LENGTH], "7");
        assert!(gz_resp.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .contains("javascript"));
        assert_eq!(to_bytes(gz_resp.into_body(), 64).await.unwrap(), b"GZBYTES".as_slice());

        let raw_resp =
            response_for_embedded(Path::new("assets/app-Ab12Cd34.js"), false, false, lookup)
                .unwrap();
        assert!(raw_resp.headers().get(header::CONTENT_ENCODING).is_none());
        assert_eq!(raw_resp.headers()[header::VARY], "Accept-Encoding");
        assert_eq!(raw_resp.headers()[header::CONTENT_LENGTH], "15");
        assert_eq!(
            to_bytes(raw_resp.into_body(), 64).await.unwrap(),
            b"console.log(1);".as_slice()
        );

        let head_resp =
            response_for_embedded(Path::new("assets/app-Ab12Cd34.js"), true, true, lookup)
                .unwrap();
        assert_eq!(head_resp.headers()[header::CONTENT_ENCODING], "gzip");
        assert_eq!(head_resp.headers()[header::CONTENT_LENGTH], "7");
        assert!(to_bytes(head_resp.into_body(), 64).await.unwrap().is_empty());

        let html_resp = response_for_embedded(Path::new("index.html"), false, true, lookup).unwrap();
        assert!(html_resp.headers().get(header::CONTENT_ENCODING).is_none());
        assert_eq!(html_resp.headers()[header::CACHE_CONTROL], NO_CACHE);
        assert_eq!(
            to_bytes(html_resp.into_body(), 64).await.unwrap(),
            b"<html>ok</html>".as_slice()
        );
    }

    #[tokio::test]
    async fn filesystem_response_negotiates_gz_sidecar_for_assets() {
        let dir = std::env::temp_dir().join(format!(
            "openbot-www-assets-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("assets")).unwrap();
        std::fs::write(dir.join("index.html"), b"<html>hi</html>").unwrap();
        std::fs::write(dir.join("assets/bundle-12345678.js"), b"const x = 1;").unwrap();
        std::fs::write(dir.join("assets/bundle-12345678.js.gz"), b"GZDATA").unwrap();
        let root = std::fs::canonicalize(&dir).unwrap();

        let gz_resp = response_for_file(
            &root,
            Path::new("assets/bundle-12345678.js"),
            false,
            true,
        )
        .await
        .unwrap();
        assert_eq!(gz_resp.headers()[header::CONTENT_ENCODING], "gzip");
        assert_eq!(gz_resp.headers()[header::VARY], "Accept-Encoding");
        assert_eq!(gz_resp.headers()[header::CACHE_CONTROL], IMMUTABLE_CACHE);
        assert_eq!(gz_resp.headers()[header::CONTENT_LENGTH], "6");
        assert!(gz_resp.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .contains("javascript"));
        assert_eq!(
            to_bytes(gz_resp.into_body(), 64).await.unwrap(),
            b"GZDATA".as_slice()
        );

        let raw_resp = response_for_file(
            &root,
            Path::new("assets/bundle-12345678.js"),
            false,
            false,
        )
        .await
        .unwrap();
        assert!(raw_resp.headers().get(header::CONTENT_ENCODING).is_none());
        assert_eq!(raw_resp.headers()[header::VARY], "Accept-Encoding");
        assert_eq!(
            to_bytes(raw_resp.into_body(), 64).await.unwrap(),
            b"const x = 1;".as_slice()
        );

        let html_resp = response_for_file(&root, Path::new("index.html"), false, true)
            .await
            .unwrap();
        assert!(html_resp.headers().get(header::CONTENT_ENCODING).is_none());
        assert_eq!(html_resp.headers()[header::CACHE_CONTROL], NO_CACHE);

        std::fs::remove_dir_all(dir).unwrap();
    }
}
