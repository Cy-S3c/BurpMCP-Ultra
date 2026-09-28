package com.burpmcp.ultra.ui

import java.awt.*
import javax.swing.*
import javax.swing.border.EmptyBorder
import javax.swing.table.JTableHeader

/**
 * BurpMCP-Ultra design system — a cohesive dark + crimson brand applied across the native Swing
 * tabs (matches the D4RK V0RT3X GitHub brand). Provides the palette, fonts, reusable components
 * (branded header, section headers, chips, styled buttons/tables), and a recursive [apply] that
 * themes our component tree while leaving Burp-native editor widgets (the `burp.*` request/response
 * editors) untouched so they keep integrating with Burp's own theme.
 */
object UiTheme {
    // ── Palette ────────────────────────────────────────────────────────────────
    val BG = Color(0x0D, 0x0F, 0x12)          // app background (near-black)
    val PANEL = Color(0x14, 0x17, 0x1C)       // panels / table body
    val ELEVATED = Color(0x1B, 0x1F, 0x26)    // inputs / headers / buttons
    val BORDER = Color(0x2A, 0x2E, 0x36)
    val CRIMSON = Color(0xE5, 0x1A, 0x2B)     // brand accent
    val CRIMSON_BRIGHT = Color(0xFF, 0x4D, 0x4D)
    val CRIMSON_DEEP = Color(0x5E, 0x0A, 0x12) // selection / gradient anchor
    val TEXT = Color(0xE6, 0xED, 0xF3)
    val TEXT_MUTED = Color(0x8B, 0x94, 0x9E)
    val SUCCESS = Color(0x3F, 0xB9, 0x50)
    val WARN = Color(0xD2, 0x99, 0x22)
    val ERROR = Color(0xF8, 0x51, 0x49)
    val INFO = Color(0x58, 0xA6, 0xFF)

    // ── Fonts ──────────────────────────────────────────────────────────────────
    // Issue #17 (中文乱码): these used to force the physical families "Segoe UI" /
    // "JetBrains Mono" on the assumption that absent families "fall back automatically".
    // They don't — a physical family has no per-glyph fallback, so on machines where the
    // family is missing (or lacks CJK glyphs, which both of these do), Chinese text
    // rendered as tofu boxes (□□) while Burp's own UI was fine. Logical font names map
    // through the JDK's fontconfig composite on every platform and carry CJK fallback,
    // so they are the safe choice for anything that may display user-language text.
    fun ui(size: Int, style: Int = Font.PLAIN): Font = Font("Dialog", style, size)
    fun mono(size: Int, style: Int = Font.PLAIN): Font = Font("Monospaced", style, size)

    private val labelDefault: Color? = UIManager.getColor("Label.foreground")

    /** Branded gradient header for the top of the extension. */
    fun brandHeader(version: String): JComponent {
        val header = object : JPanel(BorderLayout()) {
            override fun paintComponent(g: Graphics) {
                val g2 = g as Graphics2D
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
                g2.paint = GradientPaint(0f, 0f, CRIMSON_DEEP, width.toFloat(), 0f, BG)
                g2.fillRect(0, 0, width, height)
                g2.color = CRIMSON
                g2.fillRect(0, height - 2, width, 2) // crimson underline
            }
        }
        header.isOpaque = false
        header.border = EmptyBorder(10, 16, 10, 16)

        val left = JPanel().apply { isOpaque = false; layout = BoxLayout(this, BoxLayout.Y_AXIS) }
        left.add(JLabel("BurpMCP-Ultra").apply {
            font = ui(19, Font.BOLD); foreground = Color.WHITE; alignmentX = Component.LEFT_ALIGNMENT
        })
        left.add(Box.createVerticalStrut(2))
        left.add(JLabel("AI-driven MCP control for Burp Suite Professional").apply {
            font = ui(11); foreground = Color(0xF2, 0xC4, 0xC4); alignmentX = Component.LEFT_ALIGNMENT
        })

        val right = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 0)).apply { isOpaque = false }
        right.add(chip("v$version", CRIMSON))

        header.add(left, BorderLayout.WEST)
        header.add(right, BorderLayout.EAST)
        return header
    }

    /** Section header: a crimson accent bar + bold label, for structuring a panel. */
    fun sectionHeader(text: String): JComponent {
        val p = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0)).apply { isOpaque = false }
        p.add(JPanel().apply { background = CRIMSON; preferredSize = Dimension(4, 18); isOpaque = true })
        p.add(JLabel("  $text").apply { font = ui(13, Font.BOLD); foreground = TEXT })
        return p
    }

    /** A small rounded pill/chip (e.g. a status or a count). */
    fun chip(text: String, color: Color): JLabel {
        val l = object : JLabel(text, SwingConstants.CENTER) {
            override fun paintComponent(g: Graphics) {
                val g2 = g as Graphics2D
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
                g2.color = color
                g2.fillRoundRect(0, 0, width - 1, height - 1, height, height)
                super.paintComponent(g)
            }
        }
        l.foreground = Color.WHITE
        l.font = ui(11, Font.BOLD)
        l.border = EmptyBorder(3, 11, 3, 11)
        l.isOpaque = false
        return l
    }

    fun styleButton(b: AbstractButton, primary: Boolean = false) {
        b.foreground = if (primary) Color.WHITE else TEXT
        b.background = if (primary) CRIMSON else ELEVATED
        b.font = ui(12, Font.BOLD)
        b.isFocusPainted = false
        b.isOpaque = true
        b.border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(if (primary) CRIMSON else BORDER),
            EmptyBorder(5, 13, 5, 13)
        )
        b.cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
    }

    fun styleTable(t: JTable) {
        t.background = PANEL
        t.foreground = TEXT
        t.gridColor = BORDER
        t.rowHeight = maxOf(t.rowHeight, 24)
        t.selectionBackground = CRIMSON_DEEP
        t.selectionForeground = Color.WHITE
        t.showHorizontalLines = false
        t.showVerticalLines = false
        t.intercellSpacing = Dimension(0, 0)
        val h: JTableHeader = t.tableHeader ?: return
        h.background = ELEVATED
        h.foreground = CRIMSON_BRIGHT
        h.font = ui(12, Font.BOLD)
        h.border = BorderFactory.createMatteBorder(0, 0, 2, 0, CRIMSON)
        h.isOpaque = true
    }

    /**
     * Recursively themes our Swing tree. Skips `burp.*` components (Burp's own request/response
     * editors) so they keep matching Burp's theme. Per-component styling is guarded so a single odd
     * widget can never break tab construction.
     */
    fun apply(c: Component) {
        if (c.javaClass.name.startsWith("burp.")) return
        try {
            when (c) {
                is JTable -> styleTable(c)
                is JButton -> styleButton(c)
                is JToggleButton -> styleButton(c)
                is JCheckBox -> { c.foreground = TEXT; c.background = BG; c.isOpaque = false }
                is JTextField -> {
                    c.background = ELEVATED; c.foreground = TEXT; c.caretColor = CRIMSON
                    c.border = BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER), EmptyBorder(3, 6, 3, 6))
                }
                is JTextArea -> { c.background = ELEVATED; c.foreground = TEXT; c.caretColor = CRIMSON }
                is JScrollPane -> { c.background = BG; c.viewport.background = PANEL; c.border = BorderFactory.createLineBorder(BORDER) }
                is JTabbedPane -> {
                    c.background = BG; c.foreground = TEXT
                    // Burp uses FlatLaf; recolor the selected-tab underline from Burp's orange
                    // accent to brand crimson (ignored gracefully if the LAF isn't FlatLaf).
                    c.putClientProperty(
                        "FlatLaf.style",
                        "underlineColor: #E51A2B; tabSelectionHeight: 3; selectedForeground: #FF4D4D"
                    )
                }
                is JSeparator -> { c.foreground = BORDER; c.background = BG }
                is JLabel -> { if (c.foreground == labelDefault) c.foreground = TEXT }   // keep intentionally-coloured labels
                is JPanel -> { c.background = BG }
            }
        } catch (_: Exception) { /* never let theming break the UI */ }
        if (c is Container) c.components.forEach { apply(it) }
    }
}
