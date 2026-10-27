//! The image's default config (`docker/voidwall-image.toml`) against the dev
//! stack config (`docker/voidwall.toml`).
//!
//! The image config copies the dev config's guard sections. This test keeps
//! the two copies equal, and checks the modes the image starts with. Neither
//! file validates outside the image, whose model paths it names, so the test
//! compares the parsed TOML and does not load either as an `AppConfig`.

use std::path::PathBuf;

fn load(name: &str) -> toml::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docker")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    toml::from_str(&text).unwrap_or_else(|e| panic!("{} is not TOML: {e}", path.display()))
}

fn enabled(config: &toml::Value, section: &str) -> Option<bool> {
    config.get(section)?.get("enabled")?.as_bool()
}

#[test]
fn the_image_config_declares_the_dev_guards() {
    let dev = load("voidwall.toml");
    let image = load("voidwall-image.toml");
    for section in ["builtin_guards", "guards"] {
        assert!(
            dev.get(section).is_some(),
            "docker/voidwall.toml has no [{section}]"
        );
        assert_eq!(
            image.get(section),
            dev.get(section),
            "[{section}] differs between docker/voidwall-image.toml and docker/voidwall.toml",
        );
    }
}

#[test]
fn the_image_config_serves_the_rest_api_only() {
    let image = load("voidwall-image.toml");
    assert_eq!(enabled(&image, "http_api"), Some(true));
    assert_eq!(enabled(&image, "reverse_proxy"), Some(false));
}
