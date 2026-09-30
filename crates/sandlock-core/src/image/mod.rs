//! Materialize a local Docker image into a rootfs for sandboxing by
//! talking to the Docker daemon over its HTTP API (via bollard).
//!
//! `--image <ref>` resolves a *local* image only; sandlock never pulls
//! from a registry.  The daemon must be running and its socket
//! accessible: callers fail early (see [`extract`] / [`inspect_cmd`])
//! when it is not reachable, before any sandbox is built.
//!
//! The image filesystem is obtained the same way `docker export` does:
//! a throwaway stopped container is created from the image, its
//! flattened rootfs is streamed out as a tar, and unpacked into a cache
//! keyed by the image's content id.
//!
//! ```ignore
//! let rootfs = image::extract("python:3.12-slim", None).await?;
//! let cmd = image::inspect_cmd("python:3.12-slim").await?;
//! ```
//!
//! Extracted rootfs is cached at
//! `$HOME/.cache/sandlock/images/<image-id>/rootfs/` and reused on
//! subsequent invocations referencing the same image content.

use std::fs;
use std::path::{Path, PathBuf};

use bollard::models::{ContainerCreateBody, ImageInspect};
use bollard::query_parameters::RemoveContainerOptionsBuilder;
use bollard::Docker;
use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;

use crate::error::{SandboxRuntimeError, SandlockError};

mod layer;

// ============================================================
// Public API
// ============================================================

/// Default cache directory for extracted images.
fn default_cache_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".cache/sandlock/images")
}

/// Resolve a local Docker image into a cached rootfs directory.
///
/// `image_ref` is a Docker image reference (`python:3.12-slim`, a
/// digest, an image id, ...) that must already be present in local
/// Docker storage.  The extracted rootfs is keyed by the image's
/// content id so repeated calls hit the same cache.
///
/// Fails early if the Docker daemon is not reachable, or if the image
/// is not in local storage.
pub async fn extract(image_ref: &str, cache_dir: Option<&Path>) -> Result<PathBuf, SandlockError> {
    let docker = connect().await?;
    let info = inspect(&docker, image_ref).await?;
    let id = info.id.ok_or_else(|| {
        SandboxRuntimeError::Child(format!("Docker returned no id for image {image_ref}"))
    })?;

    let cache = cache_dir.map(PathBuf::from).unwrap_or_else(default_cache_dir);
    let dest = cache.join(sanitize_id(&id));
    let rootfs = dest.join("rootfs");

    // Cache hit: the .complete marker means we fully unpacked this image
    // before.  A partial directory (interrupted run) lacks the marker.
    if rootfs.is_dir() && dest.join(".complete").is_file() {
        return Ok(rootfs);
    }

    // Stale or partial cache: start clean.
    let _ = fs::remove_dir_all(&dest);
    fs::create_dir_all(&rootfs).map_err(SandboxRuntimeError::Io)?;

    // `docker create`: a stopped container we use only as an export
    // source.  No command is started.
    let body = ContainerCreateBody {
        image: Some(image_ref.to_string()),
        ..Default::default()
    };
    let created = docker
        .create_container(None, body)
        .await
        .map_err(|e| SandboxRuntimeError::Child(format!("docker create failed: {e}")))?;
    let cid = created.id;

    // `docker export`: stream the flattened rootfs to a temp tar so we
    // never hold a whole image in memory.
    let tar_path = dest.join("export.tar");
    let export_res = stream_export(&docker, &cid, &tar_path).await;

    // Always remove the throwaway container, even if the export failed.
    let _ = docker
        .remove_container(
            &cid,
            Some(RemoveContainerOptionsBuilder::new().force(true).build()),
        )
        .await;
    export_res?;

    // Unpack the tar (blocking work) off the async reactor.
    let rootfs_out = rootfs.clone();
    let tar_in = tar_path.clone();
    tokio::task::spawn_blocking(move || -> Result<(), SandlockError> {
        let tar = fs::File::open(&tar_in).map_err(SandboxRuntimeError::Io)?;
        layer::apply_layer(&rootfs_out, std::io::BufReader::new(tar))
    })
    .await
    .map_err(|e| SandboxRuntimeError::Child(format!("image unpack task failed: {e}")))??;

    let _ = fs::remove_file(&tar_path);
    fs::write(dest.join(".complete"), b"").map_err(SandboxRuntimeError::Io)?;
    Ok(rootfs)
}

/// Get the default command (Entrypoint + Cmd) for a local Docker image.
///
/// Returns the concatenation of Entrypoint and Cmd from the image
/// config, or `["/bin/sh"]` if neither is set.  Fails early if the
/// daemon is unreachable or the image is not in local storage.
pub async fn inspect_cmd(image_ref: &str) -> Result<Vec<String>, SandlockError> {
    let docker = connect().await?;
    let info = inspect(&docker, image_ref).await?;
    Ok(default_cmd(&info))
}

// ============================================================
// Docker daemon access
// ============================================================

/// Connect to the local Docker daemon and verify it is actually
/// reachable, so `--image` fails up front rather than mid-setup.
async fn connect() -> Result<Docker, SandlockError> {
    let docker = Docker::connect_with_local_defaults().map_err(daemon_unreachable)?;
    docker.ping().await.map_err(daemon_unreachable)?;
    Ok(docker)
}

fn daemon_unreachable(e: bollard::errors::Error) -> SandlockError {
    SandboxRuntimeError::Child(format!(
        "cannot reach the Docker daemon, required for --image \
         (is dockerd running and the socket accessible?): {e}"
    ))
    .into()
}

/// Inspect a local image, mapping a missing image to a clear error.
async fn inspect(docker: &Docker, image_ref: &str) -> Result<ImageInspect, SandlockError> {
    docker.inspect_image(image_ref).await.map_err(|e| {
        SandboxRuntimeError::Child(format!(
            "image not found in local Docker storage: {image_ref} ({e})"
        ))
        .into()
    })
}

/// Stream a container's exported filesystem into `tar_path`.
async fn stream_export(docker: &Docker, cid: &str, tar_path: &Path) -> Result<(), SandlockError> {
    let mut file = tokio::fs::File::create(tar_path)
        .await
        .map_err(SandboxRuntimeError::Io)?;
    let mut stream = docker.export_container(cid);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| SandboxRuntimeError::Child(format!("docker export failed: {e}")))?;
        file.write_all(&chunk).await.map_err(SandboxRuntimeError::Io)?;
    }
    file.flush().await.map_err(SandboxRuntimeError::Io)?;
    Ok(())
}

fn default_cmd(info: &ImageInspect) -> Vec<String> {
    let cfg = info.config.as_ref();
    let entrypoint = cfg.and_then(|c| c.entrypoint.clone()).unwrap_or_default();
    let cmd = cfg.and_then(|c| c.cmd.clone()).unwrap_or_default();
    let combined: Vec<String> = entrypoint.into_iter().chain(cmd).collect();
    if combined.is_empty() {
        vec!["/bin/sh".into()]
    } else {
        combined
    }
}

/// Turn an image id (`sha256:abcd...`) into a filesystem-safe cache key.
fn sanitize_id(id: &str) -> String {
    id.split_once(':').map(|(_, h)| h).unwrap_or(id).to_string()
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use bollard::models::ImageConfig;

    #[test]
    fn default_cmd_combines_entrypoint_and_cmd() {
        let info = ImageInspect {
            config: Some(ImageConfig {
                entrypoint: Some(vec!["/bin/sh".into(), "-c".into()]),
                cmd: Some(vec!["echo hi".into()]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(default_cmd(&info), vec!["/bin/sh", "-c", "echo hi"]);
    }

    #[test]
    fn default_cmd_falls_back_to_bin_sh() {
        let info = ImageInspect {
            config: Some(ImageConfig::default()),
            ..Default::default()
        };
        assert_eq!(default_cmd(&info), vec!["/bin/sh"]);
    }

    #[test]
    fn sanitize_id_strips_algorithm_prefix() {
        assert_eq!(sanitize_id("sha256:abcdef0123"), "abcdef0123");
        assert_eq!(sanitize_id("abcdef0123"), "abcdef0123");
    }
}
