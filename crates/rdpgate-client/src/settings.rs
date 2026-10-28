//! Remote Desktop connection settings: the options Remote Desktop
//! Connection (mstsc) shows under "Show Options", kept in `config.json` and
//! written into the .rdp file every time RDP Gate launches Remote Desktop.
//! Microsoft's Windows App on the Mac reads the same file and ignores what
//! it doesn't support.

use serde::{Deserialize, Deserializer, Serialize};
use std::str::FromStr;

/// How the remote desktop appears.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Display {
    FullScreen,
    AllMonitors,
    Window,
}

/// What happens when the Remote Desktop window changes size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Resize {
    /// The remote resolution follows the window.
    Resolution,
    /// The picture is scaled to fit; the remote resolution stays.
    Scale,
    /// Neither: scroll bars appear.
    Off,
}

/// Where sound from the remote computer plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Audio {
    Here,
    Remote,
    Off,
}

/// Where Windows key combinations (Alt+Tab, the Windows key) go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Keys {
    Here,
    Remote,
    FullScreen,
}

/// Connection speed, which picks how much Remote Desktop sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Speed {
    Auto,
    Lan,
    Broadband,
    Slow,
}

/// Names for the command line and labels for the app, in one place per type.
pub trait Choice: Sized + Copy + PartialEq + 'static {
    const ALL: &'static [Self];
    /// Command-line name, as stored in `config.json`.
    fn name(self) -> &'static str;
    /// What the app shows.
    fn label(self) -> &'static str;
}

macro_rules! choice {
    ($t:ty { $($v:ident => $name:literal, $label:literal;)* }) => {
        impl Choice for $t {
            const ALL: &'static [Self] = &[$(<$t>::$v),*];
            fn name(self) -> &'static str {
                match self { $(<$t>::$v => $name),* }
            }
            fn label(self) -> &'static str {
                match self { $(<$t>::$v => $label),* }
            }
        }
        impl FromStr for $t {
            type Err = String;
            fn from_str(s: &str) -> Result<Self, String> {
                Self::ALL.iter().copied().find(|c| c.name().eq_ignore_ascii_case(s)).ok_or_else(|| {
                    format!("use one of: {}", Self::ALL.iter().map(|c| c.name()).collect::<Vec<_>>().join(", "))
                })
            }
        }
    };
}

choice!(Display {
    FullScreen => "full-screen", "Full screen";
    AllMonitors => "all-monitors", "Full screen on all monitors";
    Window => "window", "In a window";
});
choice!(Resize {
    Resolution => "resolution", "Change the remote resolution";
    Scale => "scale", "Scale the picture to fit";
    Off => "off", "Do nothing (scroll bars)";
});
choice!(Audio {
    Here => "here", "Play on this computer";
    Remote => "remote", "Play on the remote computer";
    Off => "off", "Don't play";
});
choice!(Keys {
    Here => "here", "This computer";
    Remote => "remote", "The remote computer";
    FullScreen => "full-screen", "The remote computer, in full screen only";
});
choice!(Speed {
    Auto => "auto", "Detect automatically";
    Lan => "lan", "LAN (10 Mbps or more)";
    Broadband => "broadband", "Broadband (2 to 10 Mbps)";
    Slow => "slow", "Slow (under 2 Mbps)";
});

/// Display scale (percent) Remote Desktop accepts; 0 means "match this computer".
pub const SCALES: [u32; 10] = [0, 100, 125, 150, 175, 200, 250, 300, 400, 500];
/// Colour depths (bits per pixel) Remote Desktop accepts.
pub const COLORS: [u32; 4] = [32, 24, 16, 15];

/// Remote Desktop settings. Every field has a safe default, so a config
/// file from an older version (or one missing a field) still loads.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RdpSettings {
    pub display: Display,
    /// Window size in pixels, for [`Display::Window`]. 0 = match this screen.
    pub width: u32,
    pub height: u32,
    pub resize: Resize,
    /// Percent; 0 = match this computer.
    pub scale: u32,
    pub colors: u32,
    /// The bar at the top in full screen, to minimise or leave the session.
    pub connection_bar: bool,
    pub keys: Keys,
    pub clipboard: bool,
    /// All of this computer's drives, including ones plugged in later.
    pub drives: bool,
    pub printers: bool,
    pub audio: Audio,
    pub microphone: bool,
    pub cameras: bool,
    pub smart_cards: bool,
    pub speed: Speed,
    pub wallpaper: bool,
    pub font_smoothing: bool,
    /// Window animations, themes and showing a window's contents while dragging.
    pub visual_effects: bool,
    pub auto_reconnect: bool,
}

impl Default for RdpSettings {
    /// What RDP Gate always used: full screen, clipboard shared, no drives or
    /// printers. Nothing else from this computer is shared until turned on.
    fn default() -> Self {
        RdpSettings {
            display: Display::FullScreen,
            width: 0,
            height: 0,
            resize: Resize::Resolution,
            scale: 0,
            colors: 32,
            connection_bar: true,
            keys: Keys::FullScreen,
            clipboard: true,
            drives: false,
            printers: false,
            audio: Audio::Here,
            microphone: false,
            cameras: false,
            smart_cards: false,
            speed: Speed::Auto,
            wallpaper: true,
            font_smoothing: true,
            visual_effects: true,
            auto_reconnect: true,
        }
    }
}

/// Reads saved settings, falling back to the defaults instead of failing:
/// a value written by a newer version must not lock anyone out of the app.
pub fn lenient<'de, D: Deserializer<'de>>(d: D) -> Result<RdpSettings, D::Error> {
    let v = serde_json::Value::deserialize(d)?;
    Ok(serde_json::from_value(v).unwrap_or_default())
}

fn flag(on: bool) -> u8 {
    on as u8
}

impl RdpSettings {
    /// The window size to ask for, when one is set and Remote Desktop accepts it.
    pub fn window_size(&self) -> Option<(u32, u32)> {
        let ok = |v: u32| (200..=8192).contains(&v);
        (self.display == Display::Window && ok(self.width) && ok(self.height)).then_some((self.width, self.height))
    }

    /// The .rdp file lines for these settings.
    pub fn rdp_lines(&self) -> Vec<String> {
        let mut l = vec![
            format!("screen mode id:i:{}", if self.display == Display::Window { 1 } else { 2 }),
            format!("use multimon:i:{}", flag(self.display == Display::AllMonitors)),
        ];
        if let Some((w, h)) = self.window_size() {
            l.push(format!("desktopwidth:i:{w}"));
            l.push(format!("desktopheight:i:{h}"));
        }
        l.push(format!("dynamic resolution:i:{}", flag(self.resize == Resize::Resolution)));
        l.push(format!("smart sizing:i:{}", flag(self.resize == Resize::Scale)));
        if SCALES.contains(&self.scale) && self.scale != 0 {
            l.push(format!("desktopscalefactor:i:{}", self.scale));
        }
        let colors = if COLORS.contains(&self.colors) { self.colors } else { 32 };
        l.push(format!("session bpp:i:{colors}"));
        l.push(format!("displayconnectionbar:i:{}", flag(self.connection_bar)));
        let keys = match self.keys {
            Keys::Here => 0,
            Keys::Remote => 1,
            Keys::FullScreen => 2,
        };
        l.push(format!("keyboardhook:i:{keys}"));

        l.push(format!("redirectclipboard:i:{}", flag(self.clipboard)));
        l.push(format!("drivestoredirect:s:{}", if self.drives { "*" } else { "" }));
        l.push(format!("redirectprinters:i:{}", flag(self.printers)));
        let audio = match self.audio {
            Audio::Here => 0,
            Audio::Remote => 1,
            Audio::Off => 2,
        };
        l.push(format!("audiomode:i:{audio}"));
        l.push(format!("audiocapturemode:i:{}", flag(self.microphone)));
        if self.cameras {
            l.push("camerastoredirect:s:*".into());
        }
        l.push(format!("redirectsmartcards:i:{}", flag(self.smart_cards)));

        // MS-RDPBCGR connection types: 2 low-speed broadband, 4 high-speed
        // broadband, 6 LAN, 7 detect.
        let (kind, detect) = match self.speed {
            Speed::Auto => (7, 1),
            Speed::Lan => (6, 0),
            Speed::Broadband => (4, 0),
            Speed::Slow => (2, 0),
        };
        l.push(format!("connection type:i:{kind}"));
        l.push(format!("networkautodetect:i:{detect}"));
        l.push(format!("bandwidthautodetect:i:{detect}"));
        l.push(format!("disable wallpaper:i:{}", flag(!self.wallpaper)));
        l.push(format!("allow font smoothing:i:{}", flag(self.font_smoothing)));
        l.push(format!("allow desktop composition:i:{}", flag(self.visual_effects)));
        l.push(format!("disable full window drag:i:{}", flag(!self.visual_effects)));
        l.push(format!("disable menu anims:i:{}", flag(!self.visual_effects)));
        l.push(format!("disable themes:i:{}", flag(!self.visual_effects)));
        l.push("bitmapcachepersistenable:i:1".into());
        l.push(format!("autoreconnection enabled:i:{}", flag(self.auto_reconnect)));
        l
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has(lines: &[String], line: &str) -> bool {
        lines.iter().any(|l| l == line)
    }

    #[test]
    fn defaults_keep_what_rdp_gate_always_wrote() {
        let l = RdpSettings::default().rdp_lines();
        for line in ["screen mode id:i:2", "use multimon:i:0", "redirectclipboard:i:1", "redirectprinters:i:0", "drivestoredirect:s:"] {
            assert!(has(&l, line), "{line}");
        }
        assert!(has(&l, "redirectsmartcards:i:0") && has(&l, "audiocapturemode:i:0"), "nothing else shared by default");
        assert!(!l.iter().any(|x| x.starts_with("camerastoredirect") || x.starts_with("desktopwidth")));
    }

    #[test]
    fn every_setting_reaches_the_file() {
        let s = RdpSettings {
            display: Display::Window,
            width: 1600,
            height: 900,
            resize: Resize::Scale,
            scale: 150,
            colors: 16,
            connection_bar: false,
            keys: Keys::Remote,
            clipboard: false,
            drives: true,
            printers: true,
            audio: Audio::Remote,
            microphone: true,
            cameras: true,
            smart_cards: true,
            speed: Speed::Slow,
            wallpaper: false,
            font_smoothing: false,
            visual_effects: false,
            auto_reconnect: false,
        };
        let l = s.rdp_lines();
        for line in [
            "screen mode id:i:1",
            "use multimon:i:0",
            "desktopwidth:i:1600",
            "desktopheight:i:900",
            "smart sizing:i:1",
            "dynamic resolution:i:0",
            "desktopscalefactor:i:150",
            "session bpp:i:16",
            "displayconnectionbar:i:0",
            "keyboardhook:i:1",
            "redirectclipboard:i:0",
            "drivestoredirect:s:*",
            "redirectprinters:i:1",
            "audiomode:i:1",
            "audiocapturemode:i:1",
            "camerastoredirect:s:*",
            "redirectsmartcards:i:1",
            "connection type:i:2",
            "networkautodetect:i:0",
            "bandwidthautodetect:i:0",
            "disable wallpaper:i:1",
            "allow font smoothing:i:0",
            "allow desktop composition:i:0",
            "disable full window drag:i:1",
            "disable menu anims:i:1",
            "disable themes:i:1",
            "autoreconnection enabled:i:0",
        ] {
            assert!(has(&l, line), "{line}");
        }
        let all = RdpSettings { display: Display::AllMonitors, ..s };
        let l = all.rdp_lines();
        assert!(has(&l, "use multimon:i:1") && has(&l, "screen mode id:i:2"));
        assert!(!l.iter().any(|x| x.starts_with("desktopwidth")), "a window size only applies to a window");
    }

    #[test]
    fn out_of_range_values_are_ignored() {
        let s = RdpSettings { display: Display::Window, width: 50, height: 900, scale: 133, colors: 8, ..Default::default() };
        let l = s.rdp_lines();
        assert!(!l.iter().any(|x| x.starts_with("desktopwidth") || x.starts_with("desktopscalefactor")));
        assert!(has(&l, "session bpp:i:32"));
    }

    #[test]
    fn names_parse_and_unknown_config_falls_back() {
        assert_eq!("all-monitors".parse::<Display>().unwrap(), Display::AllMonitors);
        assert!("everywhere".parse::<Display>().unwrap_err().contains("full-screen"));
        for d in Display::ALL {
            assert_eq!(d.name().parse::<Display>().unwrap(), *d);
        }
        #[derive(Deserialize)]
        struct Wrap {
            #[serde(deserialize_with = "lenient")]
            rdp: RdpSettings,
        }
        let w: Wrap = serde_json::from_str(r#"{"rdp":{"display":"hologram"}}"#).unwrap();
        assert_eq!(w.rdp, RdpSettings::default());
        let w: Wrap = serde_json::from_str(r#"{"rdp":{"clipboard":false}}"#).unwrap();
        assert_eq!(w.rdp, RdpSettings { clipboard: false, ..Default::default() });
    }
}
