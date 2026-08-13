//! WebDAV backend e2e against an in-process `httpmock` server.
//!
//! These exercise the real `reqwest_dav` HTTP path — PUT/GET, HTTP Basic auth
//! header, 404 → RemoteNotFound mapping, non-2xx errors, and transport errors
//! surfaced as `Err` (never faked as "absent") — without a live WebDAV server
//! or the OS keyring. [`WebDavBackend::new_with_password`] injects credentials
//! directly so the suite runs anywhere (no Secret Service / Keychain needed).
//!
//! This is the coverage that was entirely missing before the sync overhaul:
//! the original webdav backend had only two trivial URL-formatting unit tests
//! and zero HTTP-level coverage.

#![cfg(feature = "testing")]

use avpm::config::WebDavConfig;
use avpm::sync::backend::{SyncBackend, WebDavBackend};
use avpm::sync::{SyncBackendError, SyncError};
use avpm::Error;
use httpmock::prelude::*;

const USER: &str = "u";
const PW: &str = "p";
/// base64("u:p") == "dTpw"; `reqwest_dav` assembles `Authorization: Basic dTpw`.
const BASIC_AUTH: &str = "Basic dTpw";
const BLOB: &str = "/vault.age";

fn backend_at(url: String) -> WebDavBackend {
    let cfg = WebDavConfig {
        url,
        username: USER.into(),
    };
    WebDavBackend::new_with_password(&cfg, PW.into())
}

/// `push` must PUT `vault.age` carrying the Basic-auth header and the body.
#[tokio::test]
async fn push_uploads_blob_with_basic_auth() {
    let server = MockServer::start_async().await;
    let put = server
        .mock_async(|when, then| {
            when.method(PUT)
                .path(BLOB)
                .header("Authorization", BASIC_AUTH)
                .body("encrypted-payload");
            then.status(201);
        })
        .await;

    let be = backend_at(server.url("/"));
    be.push(b"encrypted-payload", None).await.expect("push");

    put.assert_async().await; // matched method+path+auth+body
    assert_eq!(put.calls_async().await, 1);
}

/// `pull` must GET the blob and return its bytes on 2xx.
#[tokio::test]
async fn pull_downloads_blob() {
    let server = MockServer::start_async().await;
    server
        .mock_async(|when, then| {
            when.method(GET)
                .path(BLOB)
                .header("Authorization", BASIC_AUTH);
            then.status(200).body("remote-ciphertext");
        })
        .await;

    let be = backend_at(server.url("/"));
    let bytes = be.pull().await.expect("pull");
    assert_eq!(bytes, b"remote-ciphertext");
}

/// A 404 on pull must surface as `RemoteNotFound`, not a generic error.
#[tokio::test]
async fn pull_404_is_remote_not_found() {
    let server = MockServer::start_async().await;
    server
        .mock_async(|when, then| {
            when.method(GET).path(BLOB);
            then.status(404);
        })
        .await;

    let be = backend_at(server.url("/"));
    let err = be.pull().await.expect_err("404 must error");
    assert!(
        matches!(
            err,
            Error::Sync(SyncError::Backend(SyncBackendError::RemoteNotFound))
        ),
        "expected RemoteNotFound, got {err:?}"
    );
}

/// `exists` returns true on a 2xx response.
#[tokio::test]
async fn exists_true_on_success() {
    let server = MockServer::start_async().await;
    server
        .mock_async(|when, then| {
            when.method(GET).path(BLOB);
            then.status(200);
        })
        .await;

    let be = backend_at(server.url("/"));
    assert!(be.exists().await.expect("exists"));
}

/// `exists` returns false on 404 — but a transport failure must NOT look like
/// "absent" (the P1 misreporting bug).
#[tokio::test]
async fn exists_false_on_404() {
    let server = MockServer::start_async().await;
    server
        .mock_async(|when, then| {
            when.method(GET).path(BLOB);
            then.status(404);
        })
        .await;

    let be = backend_at(server.url("/"));
    assert!(!be.exists().await.expect("exists on 404"));
}

/// A push→pull round-trip through the mock server returns the same bytes.
#[tokio::test]
async fn push_pull_roundtrip() {
    let server = MockServer::start_async().await;
    server
        .mock_async(|when, then| {
            when.method(PUT).path(BLOB);
            then.status(204);
        })
        .await;
    server
        .mock_async(|when, then| {
            when.method(GET).path(BLOB);
            then.status(200).body("the-synced-blob");
        })
        .await;

    let be = backend_at(server.url("/"));
    be.push(b"the-synced-blob", None).await.expect("push");
    let back = be.pull().await.expect("pull");
    assert_eq!(back, b"the-synced-blob");
}

/// A non-2xx push (e.g. 500) must surface as an error, not a silent success.
#[tokio::test]
async fn push_5xx_errors() {
    let server = MockServer::start_async().await;
    server
        .mock_async(|when, then| {
            when.method(PUT).path(BLOB);
            then.status(500);
        })
        .await;

    let be = backend_at(server.url("/"));
    let err = be.push(b"x", None).await.expect_err("5xx must error");
    assert!(
        matches!(
            err,
            Error::Sync(SyncError::Backend(SyncBackendError::WebDav(_)))
        ),
        "expected WebDav error, got {err:?}"
    );
}

/// A transport failure (unreachable host) must surface as `Err`, never be
/// faked as a successful "absent" — this is the exists()/pull() soundness fix
/// that distinguishes "remote empty" from "can't reach remote".
#[tokio::test]
async fn transport_error_is_surfaced_not_absent() {
    // Bind a port, then drop it, so 127.0.0.1:<port> is guaranteed closed.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let be = backend_at(format!("http://127.0.0.1:{port}/"));
    let res = be.exists().await;
    assert!(
        res.is_err(),
        "transport error must surface as Err, not Ok(false); got {res:?}"
    );
}
