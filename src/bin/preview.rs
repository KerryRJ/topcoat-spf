//! Development binary for the reusable SPF panel preview.
//!
//! `topcoat dev` builds and runs this target, rebuilding when the shared
//! preview app in `examples/preview/app.rs` changes.

#[path = "../../examples/preview/app.rs"]
mod app;

#[tokio::main]
async fn main() {
    app::run().await;
}
