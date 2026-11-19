//! Compile-time and runtime-gated fault injection points for local drills.
//!
//! These hooks exist only in debug builds and only when the process explicitly
//! selects the `dev` profile and names the point. They are inert in release
//! builds and in every non-dev profile, so production binaries cannot be made
//! to abort by an inherited environment variable.

/// Terminate the current process when `stage` is the selected dev fault.
///
/// The process uses `abort` so drills observe the same abrupt boundary as a
/// machine failure: no destructors run and no buffered user-space writes are
/// flushed. Durable state must therefore already be committed before a call.
pub fn crash_point(stage: &str) {
    if !cfg!(debug_assertions) {
        return;
    }
    let Ok(profile) = std::env::var("WORKSTREAM_PROFILE") else {
        return;
    };
    if profile != "dev" {
        return;
    }
    if std::env::var("WORKSTREAM_DEV_CRASH_STAGE").as_deref() != Ok(stage) {
        return;
    }
    eprintln!("dev crash point reached: {stage}");
    std::process::abort();
}
