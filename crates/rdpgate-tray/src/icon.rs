//! Draws the tray icon: the RDP Gate shield on its blue tile, with a dot in
//! the corner for the service's state. Drawn in code at whatever size the
//! taskbar asks for, so it stays sharp at every display scale.

/// What the dot in the corner says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Running.
    Good,
    /// Starting or stopping.
    Busy,
    /// Stopped or not installed: nobody can sign in.
    Bad,
    /// The service manager couldn't be asked.
    Unknown,
}

impl Level {
    /// Stronger than the window's colours: the dot is only a few pixels.
    fn color(self) -> [f32; 3] {
        match self {
            Level::Good => [34.0, 197.0, 94.0],
            Level::Busy => [245.0, 158.0, 11.0],
            Level::Bad => [239.0, 68.0, 68.0],
            Level::Unknown => [143.0, 157.0, 194.0],
        }
    }
}

const TILE: [f32; 3] = [24.0, 50.0, 128.0];
const SHIELD: [f32; 3] = [111.0, 152.0, 247.0];
const NAVY: [f32; 3] = [11.0, 26.0, 69.0];
/// Corner radius of the tile, as a fraction of the icon.
const TILE_RADIUS: f32 = 0.22;
/// The status dot, and the transparent ring around it that keeps it apart
/// from the shield on any taskbar colour.
const DOT: (f32, f32) = (0.77, 0.77);
const DOT_RADIUS: f32 = 0.2;
const RING_RADIUS: f32 = 0.27;
/// Samples per pixel along each axis, for smooth edges.
const SAMPLES: usize = 4;

/// The shield's outline in logo units (the logo SVG's 1024 square), as in
/// rdpgate-ui's logo: straight top edges, then two curves down to the point.
fn shield_outline() -> Vec<(f32, f32)> {
    let cubic = |a: [f32; 2], b: [f32; 2], c: [f32; 2], d: [f32; 2], t: f32| {
        let u = 1.0 - t;
        let f = |i: usize| u * u * u * a[i] + 3.0 * u * u * t * b[i] + 3.0 * u * t * t * c[i] + t * t * t * d[i];
        (f(0), f(1))
    };
    let mut p = vec![(512.0, 300.0), (652.0, 352.0), (652.0, 468.0)];
    for i in 1..=12 {
        p.push(cubic([652.0, 468.0], [652.0, 556.0], [594.0, 612.0], [512.0, 646.0], i as f32 / 12.0));
    }
    for i in 1..=12 {
        p.push(cubic([512.0, 646.0], [430.0, 612.0], [372.0, 556.0], [372.0, 468.0], i as f32 / 12.0));
    }
    p.push((372.0, 352.0));
    p
}

/// Maps logo units to the icon's 0..1 square: the shield, larger than in the
/// logo (no screen around it), centred and filling most of the tile.
fn place((x, y): (f32, f32)) -> (f32, f32) {
    const TOP: f32 = 0.12;
    const HEIGHT: f32 = 0.74;
    let k = HEIGHT / 346.0; // the shield is 346 units tall
    (0.5 + (x - 512.0) * k, TOP + (y - 300.0) * k)
}

fn inside_polygon(poly: &[(f32, f32)], (x, y): (f32, f32)) -> bool {
    let mut inside = false;
    let mut j = poly.len() - 1;
    for i in 0..poly.len() {
        let ((xi, yi), (xj, yj)) = (poly[i], poly[j]);
        if (yi > y) != (yj > y) && x < (xj - xi) * (y - yi) / (yj - yi) + xi {
            inside = !inside;
        }
        j = i;
    }
    inside
}

fn inside_rounded_square((x, y): (f32, f32), r: f32) -> bool {
    if !(0.0..=1.0).contains(&x) || !(0.0..=1.0).contains(&y) {
        return false;
    }
    let dx = (r - x).max(x - (1.0 - r)).max(0.0);
    let dy = (r - y).max(y - (1.0 - r)).max(0.0);
    dx * dx + dy * dy <= r * r
}

fn within(p: (f32, f32), c: (f32, f32), r: f32) -> bool {
    let (dx, dy) = (p.0 - c.0, p.1 - c.1);
    dx * dx + dy * dy <= r * r
}

struct Shapes {
    shield: Vec<(f32, f32)>,
    keyhole: Vec<(f32, f32)>,
    keyhole_centre: (f32, f32),
    keyhole_radius: f32,
}

impl Shapes {
    fn new() -> Self {
        let keyhole = [(492.0, 462.0), (532.0, 462.0), (546.0, 560.0), (478.0, 560.0)];
        Shapes {
            shield: shield_outline().into_iter().map(place).collect(),
            keyhole: keyhole.into_iter().map(place).collect(),
            keyhole_centre: place((512.0, 440.0)),
            keyhole_radius: place((552.0, 440.0)).0 - place((512.0, 440.0)).0,
        }
    }

    /// The colour at a point of the 0..1 square, or None where it's transparent.
    fn sample(&self, p: (f32, f32), level: Level) -> Option<[f32; 3]> {
        if within(p, DOT, RING_RADIUS) {
            return within(p, DOT, DOT_RADIUS).then(|| level.color());
        }
        if !inside_rounded_square(p, TILE_RADIUS) {
            return None;
        }
        if within(p, self.keyhole_centre, self.keyhole_radius) || inside_polygon(&self.keyhole, p) {
            return Some(NAVY);
        }
        Some(if inside_polygon(&self.shield, p) { SHIELD } else { TILE })
    }
}

/// The icon as `size`×`size` pixels, top row first, each `[blue, green, red,
/// alpha]` with straight (not premultiplied) alpha: what a 32-bit Windows
/// icon bitmap holds.
pub fn render(size: usize, level: Level) -> Vec<u8> {
    let shapes = Shapes::new();
    let mut out = Vec::with_capacity(size * size * 4);
    let n = (SAMPLES * SAMPLES) as f32;
    for py in 0..size {
        for px in 0..size {
            let (mut sum, mut covered) = ([0.0f32; 3], 0.0f32);
            for sy in 0..SAMPLES {
                for sx in 0..SAMPLES {
                    let x = (px as f32 + (sx as f32 + 0.5) / SAMPLES as f32) / size as f32;
                    let y = (py as f32 + (sy as f32 + 0.5) / SAMPLES as f32) / size as f32;
                    if let Some(c) = shapes.sample((x, y), level) {
                        for (s, c) in sum.iter_mut().zip(c) {
                            *s += c;
                        }
                        covered += 1.0;
                    }
                }
            }
            if covered == 0.0 {
                out.extend([0, 0, 0, 0]);
            } else {
                let [r, g, b] = sum.map(|s| (s / covered).round() as u8);
                out.extend([b, g, r, (covered / n * 255.0).round() as u8]);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pixel(img: &[u8], size: usize, x: f32, y: f32) -> [u8; 4] {
        let (px, py) = ((x * size as f32) as usize, (y * size as f32) as usize);
        let i = (py * size + px) * 4;
        [img[i], img[i + 1], img[i + 2], img[i + 3]]
    }

    fn bgra(c: [f32; 3]) -> [u8; 4] {
        [c[2] as u8, c[1] as u8, c[0] as u8, 255]
    }

    #[test]
    fn draws_tile_shield_and_dot() {
        for size in [16, 20, 24, 32, 48] {
            let img = render(size, Level::Good);
            assert_eq!(img.len(), size * size * 4);
            assert_eq!(pixel(&img, size, 0.0, 0.0)[3], 0, "rounded corner is transparent at {size}px");
            assert_eq!(pixel(&img, size, 0.5, 0.02), bgra(TILE), "tile at {size}px");
            assert_eq!(pixel(&img, size, 0.36, 0.32), bgra(SHIELD), "shield at {size}px");
            assert_eq!(pixel(&img, size, DOT.0, DOT.1), bgra(Level::Good.color()), "dot at {size}px");
        }
    }

    #[test]
    fn each_state_has_its_own_dot() {
        let levels = [Level::Good, Level::Busy, Level::Bad, Level::Unknown];
        let dots: Vec<_> = levels.iter().map(|&l| pixel(&render(32, l), 32, DOT.0, DOT.1)).collect();
        for (i, a) in dots.iter().enumerate() {
            for b in &dots[i + 1..] {
                assert_ne!(a, b);
            }
        }
        // Only the dot changes.
        let (good, bad) = (render(32, Level::Good), render(32, Level::Bad));
        assert_eq!(pixel(&good, 32, 0.36, 0.32), pixel(&bad, 32, 0.36, 0.32));
    }

    #[test]
    fn ring_around_the_dot_is_see_through() {
        let img = render(48, Level::Bad);
        let ring = (RING_RADIUS + DOT_RADIUS) / 2.0;
        assert_eq!(pixel(&img, 48, DOT.0 - ring, DOT.1)[3], 0);
        assert_eq!(pixel(&img, 48, DOT.0, DOT.1 - ring)[3], 0);
    }
}
