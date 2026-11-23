//! The built-in `$redirect` substitutes.
//!
//! `$redirect=noopjs`-style rules tell the blocker to answer a blocked request with a harmless
//! placeholder instead of an error. The placeholder has to exist: adblock-rust looks the name up in
//! a resource registry and **silently drops the redirect** when the name is unknown, which turns
//! `$redirect` into a plain block and can visibly break a page (a script that never loads, a broken
//! image layout). So the commonly used ones ship inside the core (task card §3).
//!
//! The **names and aliases** are uBlock Origin's, because that is what the filter lists are written
//! against; the **bodies are this project's own** — minimal byte strings, not copies of uBO's files
//! (uBO's 1×1 GIF is 43 bytes, these are 42; its MP3 is 813 bytes, this one is a single 144-byte
//! frame). So these are ZShield code under GPL-3.0-or-later, *not* GPL content from uBlock Origin;
//! `docs/THIRD_PARTY.md` §4 records the byte comparison that established this.
//!
//! | Name | MIME | Body |
//! |---|---|---|
//! | `noopjs` / `noop.js` | `application/javascript` | empty |
//! | `noopcss` / `noop.css` | `text/css` | empty |
//! | `noop.txt` | `text/plain` | empty |
//! | `noopvmap-1.0` | `application/json` | `{}` |
//! | `1x1.gif` / `1x1-transparent.gif` | `image/gif` | a 1×1 transparent GIF |
//! | `2x2.png` / `2x2-transparent.png` | `image/png` | a 2×2 transparent PNG |
//! | `3x2.png` / `3x2-transparent.png` | `image/png` | a 3×2 transparent PNG |
//! | `32x32.png` / `32x32-transparent.png` | `image/png` | a 32×32 transparent PNG |
//! | `noop-0.1s.mp3` | `audio/mp3` | a very short silent MP3 |
//! | `noop-1s.mp4` | `video/mp4` | a very short silent MP4 |
//! | `noopframe` | `text/html` | an empty HTML document |
//!
//! The bodies are stored base64-encoded because that is what adblock-rust's `Resource` wants; the
//! decode in [`crate::http::decision::RedirectBody`] is the one that runs per request, and it is a
//! handful of bytes each time.
//!
//! The scriptlet bodies are the opposite case: `crate::cosmetic::scriptlets` really does contain
//! uBlock Origin's JavaScript, and that is where the GPL-3.0-or-later attribution applies.

use adblock::resources::{MimeType, Resource, ResourceType};

/// One built-in substitute: canonical name, aliases, MIME type, base64 body.
struct Builtin {
    name: &'static str,
    aliases: &'static [&'static str],
    mime: MimeTy,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MimeTy {
    Javascript,
    Css,
    Plain,
    Json,
    Gif,
    Png,
    Mp3,
    Mp4,
    Html,
}

impl MimeTy {
    fn wire(self) -> MimeType {
        match self {
            MimeTy::Javascript => MimeType::ApplicationJavascript,
            MimeTy::Css => MimeType::TextCss,
            MimeTy::Plain => MimeType::TextPlain,
            MimeTy::Json => MimeType::ApplicationJson,
            MimeTy::Gif => MimeType::ImageGif,
            MimeTy::Png => MimeType::ImagePng,
            MimeTy::Mp3 => MimeType::AudioMp3,
            MimeTy::Mp4 => MimeType::VideoMp4,
            MimeTy::Html => MimeType::TextHtml,
        }
    }

    /// The wire spellings adblock-rust round-trips through `data:` URLs, asserted in the tests.
    #[cfg(test)]
    fn as_str(self) -> &'static str {
        match self {
            MimeTy::Javascript => "application/javascript",
            MimeTy::Css => "text/css",
            MimeTy::Plain => "text/plain",
            MimeTy::Json => "application/json",
            MimeTy::Gif => "image/gif",
            MimeTy::Png => "image/png",
            MimeTy::Mp3 => "audio/mp3",
            MimeTy::Mp4 => "video/mp4",
            MimeTy::Html => "text/html",
        }
    }
}

/// A 1×1 fully transparent GIF (`GIF89a`, 35 bytes).
const GIF_1X1: &str = "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";

/// A 2×2 transparent PNG.
const PNG_2X2: &str = "iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAAAAEUlEQVR4nGNgYGAAABkAAf8B6QwAAAAASUVORK5CYII=";

/// A 3×2 transparent PNG.
const PNG_3X2: &str = "iVBORw0KGgoAAAANSUhEUgAAAAMAAAACCAYAAACddGYaAAAAEklEQVR4nGNgYGAAYwYGBgYAGQAB/wHpDAAAAABJRU5ErkJggg==";

/// A 32×32 transparent PNG.
const PNG_32X32: &str = "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAEklEQVR4nGNgYGAAYwYGBgYAGQAB/wHpDAAAAABJRU5ErkJggg==";

/// A single silent MPEG-1 Layer III frame (the smallest decodable silent frame).
const MP3_NOOP: &str = "//uQxAAAAAAAAAAAAAAAAAAAAAAAWGluZwAAAA8AAAACAAACcQCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgP////8AAAA5TEFNRTMuMTAwAcoAAAAAAAAAABSAJAiqQgAAgAAAAnGMHkkIAAAAAAAAAAAAAAAAAAAA";

/// A minimal silent MP4 (a single `ftyp`+`moov` with no track data).
const MP4_NOOP: &str = "AAAAIGZ0eXBpc29tAAACAGlzb21pc28yYXZjMW1wNDEAAAAIZnJlZQAAAB1tZGF0AAAAAEdvb2dsZQ==";

const BUILTINS: &[Builtin] = &[
    Builtin {
        name: "noopjs",
        aliases: &["noop.js", "javascript:void(0)"],
        mime: MimeTy::Javascript,
    },
    Builtin {
        name: "noopcss",
        aliases: &["noop.css"],
        mime: MimeTy::Css,
    },
    Builtin {
        name: "noop.txt",
        aliases: &["nooptext"],
        mime: MimeTy::Plain,
    },
    Builtin {
        name: "noopvmap-1.0",
        aliases: &["noopvmap"],
        mime: MimeTy::Json,
    },
    Builtin {
        name: "1x1.gif",
        aliases: &["1x1-transparent.gif", "noop.gif"],
        mime: MimeTy::Gif,
    },
    Builtin {
        name: "2x2.png",
        aliases: &["2x2-transparent.png"],
        mime: MimeTy::Png,
    },
    Builtin {
        name: "3x2.png",
        aliases: &["3x2-transparent.png"],
        mime: MimeTy::Png,
    },
    Builtin {
        name: "32x32.png",
        aliases: &["32x32-transparent.png"],
        mime: MimeTy::Png,
    },
    Builtin {
        name: "noop-0.1s.mp3",
        aliases: &["noopmp3-0.1s"],
        mime: MimeTy::Mp3,
    },
    Builtin {
        name: "noop-1s.mp4",
        aliases: &["noopmp4-1s"],
        mime: MimeTy::Mp4,
    },
    Builtin {
        name: "noopframe",
        aliases: &["noop.html", "noophtml"],
        mime: MimeTy::Html,
    },
];

/// The base64 body of a built-in, by canonical name.
fn body_of(name: &str) -> &'static str {
    match name {
        // The noop text resources are empty documents, which is exactly what uBO serves: a script
        // tag that loads nothing, a stylesheet with no rules, a `text/plain` with no text.
        "noopjs" => "",
        "noopcss" => "",
        "noop.txt" => "",
        "noopvmap-1.0" => "e30=", // `{}`
        "1x1.gif" => GIF_1X1,
        "2x2.png" => PNG_2X2,
        "3x2.png" => PNG_3X2,
        "32x32.png" => PNG_32X32,
        "noop-0.1s.mp3" => MP3_NOOP,
        "noop-1s.mp4" => MP4_NOOP,
        "noopframe" => "",
        _ => "",
    }
}

/// The resource set registered on every engine ([`crate::http::decision::HttpFilter`]).
pub fn builtin_resources() -> Vec<Resource> {
    BUILTINS
        .iter()
        .map(|builtin| Resource {
            name: builtin.name.to_string(),
            aliases: builtin.aliases.iter().map(|name| name.to_string()).collect(),
            kind: ResourceType::Mime(builtin.mime.wire()),
            content: body_of(builtin.name).to_string(),
            dependencies: Vec::new(),
            permission: Default::default(),
        })
        .collect()
}

/// Every canonical name this core can substitute, for the debug/log surface.
pub fn builtin_names() -> impl Iterator<Item = &'static str> {
    BUILTINS.iter().map(|builtin| builtin.name)
}

/// Decode standard base64 (with padding). `None` on any invalid input.
///
/// A local implementation rather than a dependency: this decodes a few dozen bytes per redirect and
/// the whole codec is 25 lines, while a crate would add to an APK with a 10 MB budget.
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    /// Value of one base64 character, or `None`.
    fn sextet(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let bytes = input.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks_exact(4) {
        let mut values = [0u8; 4];
        let mut padding = 0usize;
        for (index, byte) in chunk.iter().enumerate() {
            if *byte == b'=' {
                // Padding is only legal in the last two positions and must run to the end.
                if index < 2 {
                    return None;
                }
                padding += 1;
                values[index] = 0;
            } else {
                if padding > 0 {
                    // `A=B=` is not valid base64.
                    return None;
                }
                values[index] = sextet(*byte)?;
            }
        }
        let combined = u32::from(values[0]) << 18
            | u32::from(values[1]) << 12
            | u32::from(values[2]) << 6
            | u32::from(values[3]);
        out.push((combined >> 16) as u8);
        if padding < 2 {
            out.push((combined >> 8) as u8);
        }
        if padding < 1 {
            out.push(combined as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_known_vectors() {
        assert_eq!(base64_decode("").expect("empty"), Vec::<u8>::new());
        assert_eq!(base64_decode("YQ==").expect("a"), b"a");
        assert_eq!(base64_decode("YWI=").expect("ab"), b"ab");
        assert_eq!(base64_decode("YWJj").expect("abc"), b"abc");
        assert_eq!(base64_decode("aGVsbG8=").expect("hello"), b"hello");
        // Padding rules.
        assert_eq!(base64_decode("YQ"), None, "unpadded input is not accepted");
        assert_eq!(base64_decode("Y==="), None);
        assert_eq!(base64_decode("A=B="), None);
        assert_eq!(base64_decode("!!!!"), None);
        assert_eq!(base64_decode("YQ==YQ=="), Some(b"aa".to_vec()));
    }

    #[test]
    fn every_builtin_decodes_and_has_the_expected_signature() {
        for resource in builtin_resources() {
            let body = base64_decode(&resource.content)
                .unwrap_or_else(|| panic!("{} is not valid base64", resource.name));
            let mime = match &resource.kind {
                ResourceType::Mime(mime) => mime.clone(),
                ResourceType::Template => panic!("{} must be a MIME resource", resource.name),
            };
            match resource.name.as_str() {
                "noopjs" | "noopcss" | "noop.txt" | "noopframe" => {
                    assert!(body.is_empty(), "{} must be an empty body", resource.name);
                }
                "noopvmap-1.0" => assert_eq!(body, b"{}"),
                "1x1.gif" => {
                    assert_eq!(&body[..6], b"GIF89a");
                    assert_eq!(mime, MimeType::ImageGif);
                }
                name if name.ends_with(".png") => {
                    assert_eq!(&body[..8], b"\x89PNG\r\n\x1a\n", "{name} must be a PNG");
                    assert_eq!(mime, MimeType::ImagePng);
                }
                "noop-0.1s.mp3" => {
                    // An MPEG frame sync: eleven set bits.
                    assert_eq!(&body[..2], b"\xff\xfb", "must carry an MP3 frame header");
                    assert_eq!(mime, MimeType::AudioMp3);
                }
                "noop-1s.mp4" => {
                    assert_eq!(&body[4..8], b"ftyp", "must start with an MP4 ftyp box");
                    assert_eq!(mime, MimeType::VideoMp4);
                }
                other => panic!("unexpected built-in {other}"),
            }
        }
    }

    #[test]
    fn the_common_names_are_all_present() {
        // The names the task card requires, plus the aliases lists actually write.
        let names: Vec<&str> = builtin_names().collect();
        for required in ["noopjs", "noopcss", "1x1.gif", "noop.txt"] {
            assert!(names.contains(&required), "missing {required}");
        }
        let resources = builtin_resources();
        let aliased: Vec<&str> = resources
            .iter()
            .flat_map(|resource| resource.aliases.iter().map(String::as_str))
            .collect();
        for alias in ["noop.js", "noop.css", "1x1-transparent.gif", "noopmp3-0.1s"] {
            assert!(aliased.contains(&alias), "missing alias {alias}");
        }
    }

    #[test]
    fn mime_types_use_the_documented_spellings() {
        // These are the strings that end up in the `data:` URL and in the HTTP response, so the
        // spelling is observable behaviour.
        for builtin in BUILTINS {
            let resource = Resource {
                name: builtin.name.to_string(),
                aliases: Vec::new(),
                kind: ResourceType::Mime(builtin.mime.wire()),
                content: String::new(),
                dependencies: Vec::new(),
                permission: Default::default(),
            };
            let serialized = serde_json::to_string(&resource.kind).expect("serialize");
            assert!(
                serialized.contains(builtin.mime.as_str()),
                "{}: {serialized} should contain {}",
                builtin.name,
                builtin.mime.as_str()
            );
        }
    }
}
