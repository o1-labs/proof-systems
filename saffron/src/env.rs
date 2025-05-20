use std::{fs::File, path::Path};

use poly_commitment::{commitment::CommitmentCurve, ipa::SRS, precomputed_srs::TestSRS};
use time::macros::format_description;
use tracing::debug;
use tracing_subscriber::{
    fmt::{format::FmtSpan, time::UtcTime},
    EnvFilter,
};

pub fn get_srs_from_cache<G: CommitmentCurve>(cache: String) -> SRS<G> {
    debug!("Loading SRS from cache {}", cache);
    let file_path = Path::new(&cache);
    let file = File::open(file_path).expect("Error opening SRS cache file");
    let srs: SRS<G> = {
        // By convention, proof systems serializes a TestSRS with filename 'test_<CURVE_NAME>.srs'.
        // The benefit of using this is you don't waste time verifying the SRS.
        if file_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("test_")
        {
            let test_srs: TestSRS<G> = rmp_serde::from_read(&file).unwrap();
            From::from(test_srs)
        } else {
            rmp_serde::from_read(&file).unwrap()
        }
    };
    debug!("SRS loaded successfully from cache");
    srs
}

pub fn init_console_subscriber() {
    let timer = UtcTime::new(format_description!(
        "[year]-[month]-[day]T[hour repr:24]:[minute]:[second].[subsecond digits:3]Z"
    ));
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_span_events(FmtSpan::CLOSE)
        .with_timer(timer)
        .with_target(true)
        .with_thread_ids(false)
        .with_line_number(false)
        .with_file(false)
        .with_level(true)
        .with_ansi(true)
        .with_writer(std::io::stdout)
        .init();
}

#[cfg(test)]
#[ctor::ctor]
fn init_test_logging() {
    init_console_subscriber();
}
