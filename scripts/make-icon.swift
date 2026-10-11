// Draws the app icon. Regenerate assets/AppIcon.icns with: ./scripts/make-icon.sh
import AppKit

let size: CGFloat = 1024
let image = NSImage(size: NSSize(width: size, height: size))
image.lockFocus()
let ctx = NSGraphicsContext.current!.cgContext

// Background: rounded square with a deep blue gradient (macOS icon grid: 824pt body, 100pt inset).
let body = CGRect(x: 100, y: 100, width: 824, height: 824)
let bg = CGPath(roundedRect: body, cornerWidth: 185, cornerHeight: 185, transform: nil)
ctx.saveGState()
ctx.addPath(bg)
ctx.clip()
let colors = [NSColor(red: 0.11, green: 0.20, blue: 0.42, alpha: 1).cgColor,
              NSColor(red: 0.04, green: 0.08, blue: 0.18, alpha: 1).cgColor] as CFArray
let gradient = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: colors, locations: [0, 1])!
ctx.drawLinearGradient(gradient, start: CGPoint(x: 512, y: 924), end: CGPoint(x: 512, y: 100), options: [])
ctx.restoreGState()

// Log page.
let page = CGRect(x: 250, y: 210, width: 420, height: 560)
ctx.setFillColor(NSColor(white: 0.96, alpha: 1).cgColor)
ctx.addPath(CGPath(roundedRect: page, cornerWidth: 36, cornerHeight: 36, transform: nil))
ctx.fillPath()

// Event rows: severity dot + line, like the table in the app.
let rows: [(NSColor, CGFloat)] = [
    (NSColor(red: 0.30, green: 0.56, blue: 0.92, alpha: 1), 0.85),
    (NSColor(red: 0.30, green: 0.56, blue: 0.92, alpha: 1), 0.65),
    (NSColor(red: 0.93, green: 0.69, blue: 0.20, alpha: 1), 0.75),
    (NSColor(red: 0.30, green: 0.56, blue: 0.92, alpha: 1), 0.55),
    (NSColor(red: 0.88, green: 0.30, blue: 0.33, alpha: 1), 0.80),
    (NSColor(red: 0.30, green: 0.56, blue: 0.92, alpha: 1), 0.60),
]
for (i, (color, frac)) in rows.enumerated() {
    let y = page.maxY - 95 - CGFloat(i) * 78
    ctx.setFillColor(color.cgColor)
    ctx.fillEllipse(in: CGRect(x: page.minX + 45, y: y - 15, width: 30, height: 30))
    ctx.setFillColor(NSColor(white: 0.70, alpha: 1).cgColor)
    let w = (page.width - 150) * frac
    ctx.addPath(CGPath(roundedRect: CGRect(x: page.minX + 100, y: y - 11, width: w, height: 22),
                       cornerWidth: 11, cornerHeight: 11, transform: nil))
    ctx.fillPath()
}

// Magnifying glass.
let center = CGPoint(x: 640, y: 400)
let radius: CGFloat = 130
ctx.setLineCap(.butt)
ctx.setStrokeColor(NSColor(red: 0.98, green: 0.80, blue: 0.30, alpha: 1).cgColor)
ctx.setLineWidth(64)
let start = (radius + 22) * 0.7071
ctx.move(to: CGPoint(x: center.x + start, y: center.y - start))
ctx.addLine(to: CGPoint(x: 805, y: 235))
ctx.strokePath()
// Round only the outer end of the handle.
ctx.setFillColor(NSColor(red: 0.98, green: 0.80, blue: 0.30, alpha: 1).cgColor)
ctx.fillEllipse(in: CGRect(x: 805 - 32, y: 235 - 32, width: 64, height: 64))
ctx.setFillColor(NSColor(red: 0.55, green: 0.78, blue: 1.0, alpha: 0.35).cgColor)
ctx.fillEllipse(in: CGRect(x: center.x - radius, y: center.y - radius, width: radius * 2, height: radius * 2))
ctx.setStrokeColor(NSColor(red: 0.98, green: 0.80, blue: 0.30, alpha: 1).cgColor)
ctx.setLineWidth(40)
ctx.strokeEllipse(in: CGRect(x: center.x - radius, y: center.y - radius, width: radius * 2, height: radius * 2))

image.unlockFocus()
let rep = NSBitmapImageRep(data: image.tiffRepresentation!)!
let png = rep.representation(using: .png, properties: [:])!
try! png.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
