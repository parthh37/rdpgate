//! The look shared by the RDP Gate app and the RDP Gate Server window: a dark
//! navy theme matching the website and the logo, cards, status pills, a step
//! indicator and the logo itself, drawn so no image decoder is needed.

use egui::{
    Align2, Color32, CornerRadius, FontId, Margin, Pos2, Rect, Response, RichText, Sense, Shadow, Shape, Stroke,
    StrokeKind, TextStyle, Ui, pos2, vec2,
};

const fn rgb(r: u8, g: u8, b: u8) -> Color32 {
    Color32::from_rgb(r, g, b)
}

/// Window background.
pub const BG: Color32 = rgb(9, 17, 40);
/// Side and top bars, a step darker than the window.
pub const BAR: Color32 = rgb(6, 12, 30);
pub const CARD: Color32 = rgb(15, 28, 62);
pub const BORDER: Color32 = rgb(33, 51, 102);
/// Text fields and code: sunk below the card.
pub const INPUT: Color32 = rgb(7, 14, 34);
pub const TEXT: Color32 = rgb(229, 234, 246);
pub const MUTED: Color32 = rgb(143, 157, 194);
pub const ACCENT: Color32 = rgb(59, 108, 240);
const ACCENT_HOVER: Color32 = rgb(86, 132, 255);
pub const GOOD: Color32 = rgb(70, 212, 160);
pub const BAD: Color32 = rgb(255, 125, 114);
pub const WARN: Color32 = rgb(243, 180, 82);

/// What a pill, dot or notice is saying.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tone {
    Good,
    Bad,
    Warn,
    Info,
    Neutral,
}

impl Tone {
    pub fn color(self) -> Color32 {
        match self {
            Tone::Good => GOOD,
            Tone::Bad => BAD,
            Tone::Warn => WARN,
            Tone::Info => ACCENT_HOVER,
            Tone::Neutral => MUTED,
        }
    }

    pub fn from_ok(ok: bool) -> Tone {
        if ok { Tone::Good } else { Tone::Bad }
    }

    fn tint(self, alpha: u8) -> Color32 {
        let c = self.color();
        Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), alpha)
    }
}

/// Installs the theme. Always dark: it is the brand, and it keeps the
/// windows looking the same on every system.
pub fn apply(ctx: &egui::Context) {
    ctx.set_theme(egui::ThemePreference::Dark);
    ctx.style_mut_of(egui::Theme::Dark, |s| {
        use TextStyle::*;
        s.text_styles = [
            (Heading, FontId::proportional(22.0)),
            (Body, FontId::proportional(14.0)),
            (Button, FontId::proportional(14.0)),
            (Small, FontId::proportional(12.0)),
            (Monospace, FontId::monospace(13.0)),
        ]
        .into();
        s.spacing.item_spacing = vec2(8.0, 8.0);
        s.spacing.button_padding = vec2(12.0, 6.0);
        s.spacing.interact_size.y = 30.0;
        s.spacing.indent = 18.0;

        let v = &mut s.visuals;
        v.panel_fill = BG;
        v.window_fill = CARD;
        v.window_stroke = Stroke::new(1.0, BORDER);
        v.window_corner_radius = CornerRadius::same(14);
        v.window_shadow = Shadow { offset: [0, 16], blur: 40, spread: 0, color: Color32::from_black_alpha(140) };
        v.popup_shadow = Shadow { offset: [0, 8], blur: 20, spread: 0, color: Color32::from_black_alpha(120) };
        v.menu_corner_radius = CornerRadius::same(10);
        v.extreme_bg_color = INPUT;
        v.faint_bg_color = rgb(19, 34, 74);
        v.code_bg_color = INPUT;
        v.hyperlink_color = ACCENT_HOVER;
        v.warn_fg_color = WARN;
        v.error_fg_color = BAD;
        v.selection.bg_fill = Color32::from_rgba_unmultiplied(59, 108, 240, 110);
        v.selection.stroke = Stroke::new(1.0, TEXT);
        v.text_cursor.stroke = Stroke::new(2.0, ACCENT_HOVER);
        v.striped = true;

        let w = &mut v.widgets;
        let radius = CornerRadius::same(8);
        w.noninteractive.bg_fill = CARD;
        w.noninteractive.weak_bg_fill = CARD;
        w.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
        w.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
        w.noninteractive.corner_radius = radius;
        for (state, fill, stroke, text) in [
            (&mut w.inactive, rgb(24, 40, 84), BORDER, TEXT),
            (&mut w.hovered, rgb(32, 52, 108), rgb(63, 88, 160), Color32::WHITE),
            (&mut w.active, rgb(38, 62, 128), ACCENT, Color32::WHITE),
            (&mut w.open, rgb(32, 52, 108), BORDER, TEXT),
        ] {
            state.bg_fill = fill;
            state.weak_bg_fill = fill;
            state.bg_stroke = Stroke::new(1.0, stroke);
            state.fg_stroke = Stroke::new(1.5, text);
            state.corner_radius = radius;
            state.expansion = 0.0;
        }
    });
}

/// The one prominent action on each screen.
pub fn primary(label: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(label).strong().color(Color32::WHITE))
        .fill(ACCENT)
        .stroke(Stroke::new(1.0, ACCENT_HOVER))
        .corner_radius(CornerRadius::same(9))
        .min_size(vec2(180.0, 36.0))
}

/// A primary button across the whole width of the card it's in.
pub fn primary_wide(ui: &mut Ui, enabled: bool, label: &str) -> Response {
    let width = ui.available_width();
    ui.add_enabled(enabled, primary(label).min_size(vec2(width, 40.0)))
}

/// A raised panel that groups one thing, as wide as there's room for.
pub fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(14))
        .inner_margin(Margin::same(18))
        .shadow(Shadow { offset: [0, 6], blur: 18, spread: 0, color: Color32::from_black_alpha(60) })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// A card with a title and an optional line under it.
pub fn titled_card<R>(ui: &mut Ui, title: &str, subtitle: Option<&str>, add: impl FnOnce(&mut Ui) -> R) -> R {
    card(ui, |ui| {
        ui.label(RichText::new(title).strong().size(16.0).color(TEXT));
        if let Some(s) = subtitle {
            ui.label(RichText::new(s).color(MUTED));
        }
        ui.add_space(6.0);
        add(ui)
    })
}

/// A page's heading with a line of explanation under it.
pub fn page_title(ui: &mut Ui, title: &str, subtitle: &str) {
    ui.label(RichText::new(title).heading().strong().color(TEXT));
    if !subtitle.is_empty() {
        ui.label(RichText::new(subtitle).color(MUTED));
    }
    ui.add_space(10.0);
}

/// A small label above a field.
pub fn field_label(ui: &mut Ui, text: &str) -> Response {
    ui.label(RichText::new(text).small().strong().color(MUTED))
}

pub fn muted(text: impl Into<String>) -> RichText {
    RichText::new(text).color(MUTED)
}

/// A rounded, tinted label with a dot: "● Running".
pub fn pill(ui: &mut Ui, tone: Tone, text: &str) -> Response {
    // Painted rather than laid out, so it looks the same in any layout.
    let galley = ui.painter().layout_no_wrap(text.to_string(), FontId::proportional(12.0), tone.color());
    let size = vec2(galley.size().x + 32.0, 22.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::hover());
    let p = ui.painter();
    p.rect_filled(rect, CornerRadius::same(255), tone.tint(34));
    p.rect_stroke(rect, CornerRadius::same(255), Stroke::new(1.0, tone.tint(90)), StrokeKind::Inside);
    let dot = pos2(rect.min.x + 12.0, rect.center().y);
    p.circle_filled(dot, 5.5, tone.tint(45));
    p.circle_filled(dot, 3.0, tone.color());
    p.galley(pos2(rect.min.x + 22.0, rect.center().y - galley.size().y / 2.0), galley, tone.color());
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Label, true, text));
    response
}

/// A small status light.
pub fn dot(ui: &mut Ui, tone: Tone) {
    let (rect, _) = ui.allocate_exact_size(vec2(8.0, 8.0), Sense::hover());
    let p = ui.painter();
    p.circle_filled(rect.center(), 6.0, tone.tint(40));
    p.circle_filled(rect.center(), 3.5, tone.color());
}

/// A tinted box with a message. With `dismiss`, it has a close button and
/// returns true once that's clicked.
pub fn notice(ui: &mut Ui, tone: Tone, text: &str, dismiss: bool) -> bool {
    let mut closed = false;
    egui::Frame::new()
        .fill(tone.tint(26))
        .stroke(Stroke::new(1.0, tone.tint(100)))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(12, 9))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                dot(ui, tone);
                if dismiss {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        closed = ui.add(egui::Button::new(muted("×").size(18.0)).frame(false)).on_hover_text("Dismiss").clicked();
                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                            ui.add(egui::Label::new(RichText::new(text).color(tone.color())).wrap());
                        });
                    });
                } else {
                    ui.add(egui::Label::new(RichText::new(text).color(tone.color())).wrap());
                }
            });
        });
    closed
}

/// A wizard's progress: done steps get a tick, the current one is lit.
pub fn steps(ui: &mut Ui, labels: &[&str], current: usize) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        for (i, label) in labels.iter().enumerate() {
            if i > 0 {
                let (rect, _) = ui.allocate_exact_size(vec2(22.0, 22.0), Sense::hover());
                let color = if i <= current { ACCENT } else { BORDER };
                ui.painter().line_segment([rect.left_center(), rect.right_center()], Stroke::new(2.0, color));
            }
            let (rect, _) = ui.allocate_exact_size(vec2(22.0, 22.0), Sense::hover());
            let p = ui.painter();
            let c = rect.center();
            let font = FontId::proportional(12.0);
            if i < current {
                p.circle_filled(c, 11.0, GOOD);
                let tick = [c + vec2(-4.5, 0.5), c + vec2(-1.5, 3.5), c + vec2(4.5, -3.0)];
                p.line_segment([tick[0], tick[1]], Stroke::new(2.0, BG));
                p.line_segment([tick[1], tick[2]], Stroke::new(2.0, BG));
            } else if i == current {
                p.circle_filled(c, 13.0, Color32::from_rgba_unmultiplied(59, 108, 240, 60));
                p.circle_filled(c, 11.0, ACCENT);
                p.text(c, Align2::CENTER_CENTER, (i + 1).to_string(), font, Color32::WHITE);
            } else {
                p.circle_stroke(c, 10.5, Stroke::new(1.5, BORDER));
                p.text(c, Align2::CENTER_CENTER, (i + 1).to_string(), font, MUTED);
            }
            let text = RichText::new(*label).small().strong();
            ui.label(if i == current { text.color(TEXT) } else { text.color(MUTED) });
        }
    });
}

/// The logo (docs/assets/logo.svg): a screen behind a shield with a keyhole.
pub fn logo(ui: &mut Ui, size: f32) -> Response {
    let (rect, response) = ui.allocate_exact_size(vec2(size, size), Sense::hover());
    paint_logo(ui.painter(), rect);
    response
}

fn paint_logo(p: &egui::Painter, rect: Rect) {
    // The SVG's tile spans 64..960 of a 1024 square.
    let s = rect.width() / 896.0;
    let at = |x: f32, y: f32| pos2(rect.min.x + (x - 64.0) * s, rect.min.y + (y - 64.0) * s);
    let r = |x0: f32, y0: f32, x1: f32, y1: f32| Rect::from_min_max(at(x0, y0), at(x1, y1));
    let radius = |v: f32| CornerRadius::same((v * s).round().clamp(0.0, 255.0) as u8);
    let navy = rgb(11, 26, 69);
    let white = Color32::from_white_alpha(230);

    p.rect_filled(rect, radius(200.0), rgb(24, 50, 128));
    p.rect_stroke(r(232.0, 250.0, 792.0, 630.0), radius(44.0), Stroke::new(40.0 * s, white), StrokeKind::Middle);
    p.rect_filled(r(452.0, 630.0, 572.0, 700.0), 0.0, white);
    p.rect_filled(r(352.0, 700.0, 672.0, 740.0), radius(20.0), white);

    // Shield: straight top edges, then two cubic curves down to the point.
    let mut shield = vec![at(512.0, 300.0), at(652.0, 352.0), at(652.0, 468.0)];
    let cubic = |a: [f32; 2], b: [f32; 2], c: [f32; 2], d: [f32; 2], t: f32| {
        let u = 1.0 - t;
        let f = |i: usize| u * u * u * a[i] + 3.0 * u * u * t * b[i] + 3.0 * u * t * t * c[i] + t * t * t * d[i];
        at(f(0), f(1))
    };
    for i in 1..=8 {
        shield.push(cubic([652.0, 468.0], [652.0, 556.0], [594.0, 612.0], [512.0, 646.0], i as f32 / 8.0));
    }
    for i in 1..=8 {
        shield.push(cubic([512.0, 646.0], [430.0, 612.0], [372.0, 556.0], [372.0, 468.0], i as f32 / 8.0));
    }
    shield.push(at(372.0, 352.0));
    p.add(Shape::convex_polygon(shield, rgb(111, 152, 247), Stroke::new(22.0 * s, navy)));

    p.circle_filled(at(512.0, 440.0), 40.0 * s, navy);
    let keyhole: Vec<Pos2> = vec![at(492.0, 462.0), at(532.0, 462.0), at(546.0, 560.0), at(478.0, 560.0)];
    p.add(Shape::convex_polygon(keyhole, navy, Stroke::NONE));
}

/// Logo and product name, for the top of a window.
pub fn brand(ui: &mut Ui, name: &str, tagline: &str) {
    ui.horizontal(|ui| {
        logo(ui, 34.0);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            ui.label(RichText::new(name).strong().size(16.0).color(TEXT));
            ui.label(RichText::new(tagline).small().color(MUTED));
        });
    });
}

/// A box for a line or two of code (keys, commands, cards) that you can
/// select and copy but not edit.
pub fn code_box(ui: &mut Ui, text: &str, rows: usize) -> Response {
    let mut shown = text.to_string();
    let edit = egui::TextEdit::multiline(&mut shown)
        .font(TextStyle::Monospace)
        .desired_rows(rows)
        .desired_width(f32::INFINITY)
        .margin(Margin::symmetric(10, 8));
    ui.add(edit)
}

/// A one-line code box that never wraps (see the enroll command).
pub fn code_line(ui: &mut Ui, text: &str) -> Response {
    let mut shown = text.to_string();
    ui.add(
        egui::TextEdit::singleline(&mut shown)
            .font(TextStyle::Monospace)
            .desired_width(f32::INFINITY)
            .margin(Margin::symmetric(10, 8)),
    )
}
