//! Runnable browser preview for the reusable SPF panel.
//!
//! This example and the `preview` development binary share
//! `examples/preview/app.rs`; the server itself lives there.
//!
//! Run the example with:
//!
//! ```sh
//! cargo run --example preview --features preview
//! ```
//!
//! and open <http://127.0.0.1:3000/>.

#[path = "preview/app.rs"]
mod app;

#[tokio::main]
async fn main() {
    app::run().await;
}
