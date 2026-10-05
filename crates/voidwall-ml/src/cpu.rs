//! The minimum CPU the binary runs on.
//!
//! The linked ONNX Runtime build needs x86-64-v3. On an older CPU the process
//! would die with an illegal instruction somewhere inside a run, so the binary
//! checks first and refuses to start with a message that names the gap.

/// The name of the minimum CPU level, as error messages state it.
pub const MIN_CPU_LEVEL: &str = "x86-64-v3";

/// The x86-64-v3 feature set, including the v2 features it builds on.
const REQUIRED_FEATURES: &[&str] = &[
    "sse3",
    "ssse3",
    "sse4.1",
    "sse4.2",
    "popcnt",
    "cmpxchg16b",
    "avx",
    "avx2",
    "bmi1",
    "bmi2",
    "f16c",
    "fma",
    "lzcnt",
    "movbe",
    "xsave",
];

/// Returns the x86-64-v3 features this CPU lacks; empty when it meets the floor.
pub fn missing_features() -> Vec<&'static str> {
    missing_from(|feature| match feature {
        "sse3" => std::is_x86_feature_detected!("sse3"),
        "ssse3" => std::is_x86_feature_detected!("ssse3"),
        "sse4.1" => std::is_x86_feature_detected!("sse4.1"),
        "sse4.2" => std::is_x86_feature_detected!("sse4.2"),
        "popcnt" => std::is_x86_feature_detected!("popcnt"),
        "cmpxchg16b" => std::is_x86_feature_detected!("cmpxchg16b"),
        "avx" => std::is_x86_feature_detected!("avx"),
        "avx2" => std::is_x86_feature_detected!("avx2"),
        "bmi1" => std::is_x86_feature_detected!("bmi1"),
        "bmi2" => std::is_x86_feature_detected!("bmi2"),
        "f16c" => std::is_x86_feature_detected!("f16c"),
        "fma" => std::is_x86_feature_detected!("fma"),
        "lzcnt" => std::is_x86_feature_detected!("lzcnt"),
        "movbe" => std::is_x86_feature_detected!("movbe"),
        "xsave" => std::is_x86_feature_detected!("xsave"),
        _ => unreachable!("every required feature has a detector arm"),
    })
}

fn missing_from(has: impl Fn(&str) -> bool) -> Vec<&'static str> {
    REQUIRED_FEATURES
        .iter()
        .copied()
        .filter(|f| !has(f))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(&[], &[] ; "every feature present")]
    #[test_case(&["avx2"], &["avx2"] ; "one feature missing")]
    #[test_case(&["fma", "avx", "movbe"], &["avx", "fma", "movbe"] ; "several missing in canonical order")]
    fn reports_the_features_the_cpu_lacks(absent: &[&str], expected: &[&str]) {
        assert_eq!(missing_from(|f| !absent.contains(&f)), expected);
    }

    #[test]
    fn every_required_feature_has_a_detector() {
        // Panics on a feature added to the list without a detector arm.
        let _ = missing_features();
    }
}
