# --------- HeadYangDer          ---------
# --------- Burp Suite Extension ---------
# --------- XD                   ---------
# --------- GL                   ---------
# --------- TQ                   ---------
# --------- Born at 22/8/2025    ---------

# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IContextMenuFactory
from javax.swing import JPanel, JTable, JScrollPane, JMenuItem, JButton, JCheckBox, BoxLayout, Box, JSlider, JLabel, BorderFactory, JFileChooser
from java.awt import BorderLayout, Font, Dimension, Color
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.imageio import ImageIO
from java.awt.image import BufferedImage
import java.io.File as File
import re

# --- Valid patterns for headers ---
HEADERS_TO_CHECK = {
    "Strict-Transport-Security": [
        re.compile(r"max-age=\d+$"),
        re.compile(r"max-age=\d+; includeSubDomains$"),
        re.compile(r"max-age=\d+; includeSubDomains; preload$"),
        re.compile(r"max-age=\d+; preload$"),
    ],
    "Content-Security-Policy": [
        re.compile(r".+"),  # any CSP is accepted
    ],
    "X-Frame-Options": [
        re.compile(r"DENY$", re.IGNORECASE),
        re.compile(r"SAMEORIGIN$", re.IGNORECASE),
        re.compile(r"ALLOW-FROM .+", re.IGNORECASE),
    ],
    "X-Content-Type-Options": [
        re.compile(r"nosniff$", re.IGNORECASE),
    ],
    "Referrer-Policy": [
        re.compile(r"no-referrer$", re.IGNORECASE),
        re.compile(r"no-referrer-when-downgrade$", re.IGNORECASE),
        re.compile(r"same-origin$", re.IGNORECASE),
        re.compile(r"origin$", re.IGNORECASE),
        re.compile(r"strict-origin$", re.IGNORECASE),
        re.compile(r"strict-origin-when-cross-origin$", re.IGNORECASE),
        re.compile(r"unsafe-url$", re.IGNORECASE),
    ],
    "Permissions-Policy": [
        re.compile(r".+"),  # any policy is accepted
    ]
}

# Default sort order
DEFAULT_ORDER = [
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

DEFAULT_FONT_SIZE = 24
DEFAULT_COLUMN_WIDTHS = [200, 100, 400]
DEFAULT_PADDING = 60
DEFAULT_ROW_PADDING = 15
DEFAULT_BOTTOM_SPACE = 40

# --- Custom Renderer for Status column ---
class StatusCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        comp = super(StatusCellRenderer, self).getTableCellRendererComponent(
            table, value, isSelected, hasFocus, row, column
        )
        if column == 1:  # Status column
            if value == "OK":
                comp.setForeground(Color(0, 128, 0))
            elif value == "Missing":
                comp.setForeground(Color.RED)
            elif value == "Incorrect":
                comp.setForeground(Color.ORANGE)
            else:
                comp.setForeground(Color.BLACK)
        else:
            comp.setForeground(Color.BLACK)
        return comp

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("HeadYangDer")

        self.last_message = None
        self.font_size = DEFAULT_FONT_SIZE
        self.font = Font("Arial", Font.PLAIN, self.font_size)
        self.table_header_font = Font("Arial", Font.BOLD, self.font_size)
        self.default_view_font = Font("Arial", Font.PLAIN, self.font_size + 2)
        self.site_font = Font("Arial", Font.BOLD, self.font_size)
        self.padding = DEFAULT_PADDING

        # --- UI Panel ---
        self.panel = JPanel(BorderLayout())

        # Left panel: checkboxes
        self.checkboxPanel = JPanel()
        self.checkboxPanel.setLayout(BoxLayout(self.checkboxPanel, BoxLayout.Y_AXIS))
        self.headerCheckboxes = {}
        for h in DEFAULT_ORDER:
            cb = JCheckBox(h, True)
            cb.setFont(self.font)
            cb.addActionListener(lambda e, hn=h: self.update_table_from_last())
            self.checkboxPanel.add(cb)
            self.headerCheckboxes[h] = cb
        self.panel.add(self.checkboxPanel, BorderLayout.WEST)

        # Center panel
        self.tablePanel = JPanel(BorderLayout())
        self.contentPanel = JPanel(BorderLayout())
        self.tablePanel.add(self.contentPanel, BorderLayout.CENTER)

        self.paddedPanel = JPanel(BorderLayout())
        self.paddedPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, DEFAULT_BOTTOM_SPACE, 0))
        self.leftPadding = Box.createHorizontalStrut(self.padding)
        self.rightPadding = Box.createHorizontalStrut(self.padding)
        self.paddedPanel.add(self.leftPadding, BorderLayout.WEST)
        self.paddedPanel.add(self.rightPadding, BorderLayout.EAST)

        # Site label
        self.siteLabel = JLabel("No request scanned yet")
        self.siteLabel.setFont(self.site_font)
        self.siteLabel.setOpaque(False)
        self.siteLabel.setHorizontalAlignment(JLabel.CENTER)
        self.siteLabel.setPreferredSize(Dimension(sum(DEFAULT_COLUMN_WIDTHS) + 2 * self.padding, self.font_size + 10))
        self.tablePanel.add(self.siteLabel, BorderLayout.NORTH)

        # Main table
        self.model = DefaultTableModel(["Header", "Status", "Details"], 0)
        self.table = JTable(self.model)
        self.table.getTableHeader().setReorderingAllowed(True)
        self.table.getTableHeader().setFont(self.table_header_font)
        self.table.setFont(self.font)
        self.table.setRowHeight(self.font_size + DEFAULT_ROW_PADDING)
        self.table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)

        self.table.getColumnModel().getColumn(1).setCellRenderer(StatusCellRenderer())

        # No scrollbars
        self.scrollPane = JScrollPane(self.table,
                                      JScrollPane.VERTICAL_SCROLLBAR_NEVER,
                                      JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        self.paddedPanel.add(self.scrollPane, BorderLayout.CENTER)
        self.contentPanel.add(self.paddedPanel, BorderLayout.NORTH)

        self.panel.add(self.tablePanel, BorderLayout.CENTER)

        # Top panel: controls
        self.topPanel = JPanel()
        self.zoomIn = JButton("Zoom +", actionPerformed=lambda e: self.change_font_size(2))
        self.zoomIn.setFont(self.font)
        self.zoomOut = JButton("Zoom -", actionPerformed=lambda e: self.change_font_size(-2))
        self.zoomOut.setFont(self.font)
        self.defaultView = JButton("Default View", actionPerformed=lambda e: self.reset_default_view())
        self.defaultView.setFont(self.default_view_font)
        self.clearSelection = JButton("Clear Selection", actionPerformed=lambda e: self.table.clearSelection())
        self.clearSelection.setFont(self.font)
        self.exportButton = JButton("Export Image", actionPerformed=lambda e: self.export_image())
        self.exportButton.setFont(self.font)

        self.topPanel.add(self.zoomIn)
        self.topPanel.add(self.zoomOut)
        self.topPanel.add(self.defaultView)
        self.topPanel.add(self.clearSelection)
        self.topPanel.add(self.exportButton)

        self.topPanel.add(JLabel("Padding:"))
        self.paddingSlider = JSlider(0, 100, self.padding)
        self.paddingSlider.setPreferredSize(Dimension(120, 40))
        self.paddingSlider.addChangeListener(lambda e: self.update_padding(self.paddingSlider.getValue()))
        self.topPanel.add(self.paddingSlider)

        self.panel.add(self.topPanel, BorderLayout.NORTH)

        # Register
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)

    # ITab
    def getTabCaption(self):
        return "HeadYangDer"

    def getUiComponent(self):
        return self.panel

    # Context menu
    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return None
        menuItem = JMenuItem("Send to Header Checker", actionPerformed=lambda x: self.scan_headers(messages[0]))
        return [menuItem]

    # Scanning
    def scan_headers(self, message):
        self.last_message = message
        self.model.setRowCount(0)

        if message:
            request_info = self.helpers.analyzeRequest(message)
            url = request_info.getUrl()
            host = url.getHost()
            self.siteLabel.setText("%s (%s)" % (host, url.toString()))
        else:
            self.siteLabel.setText("No request scanned yet")

        response = message.getResponse()
        if not response:
            self.model.addRow(["No Response", "N/A", "Empty"])
            self.update_table_size()
            return

        analyzed = self.helpers.analyzeResponse(response)
        headers = analyzed.getHeaders()

        header_dict = {}
        for h in headers:
            if ":" in h:
                name, value = h.split(":", 1)
                header_dict[name.strip()] = value.strip()

        temp_results = {}
        for hname, patterns in HEADERS_TO_CHECK.items():
            if not self.headerCheckboxes[hname].isSelected():
                continue
            if hname in header_dict:
                value = header_dict[hname]
                status = "Incorrect"
                for pattern in patterns:
                    if pattern.match(value):
                        status = "OK"
                        break
            else:
                status = "Missing"
                value = "Not Found"
            temp_results[hname] = (status, value)

        for h in DEFAULT_ORDER:
            if h in temp_results:
                self.model.addRow([h, temp_results[h][0], temp_results[h][1]])

        self.reset_column_widths()
        self.table.clearSelection()
        self.update_table_size()

    def update_table_size(self):
        row_count = self.model.getRowCount()
        header_height = self.table.getTableHeader().getPreferredSize().height
        row_height = self.table.getRowHeight()
        total_height = header_height + (row_count * row_height) + DEFAULT_BOTTOM_SPACE
        self.table.setPreferredSize(Dimension(sum(DEFAULT_COLUMN_WIDTHS) + 2 * self.padding, total_height))
        self.scrollPane.setPreferredSize(Dimension(sum(DEFAULT_COLUMN_WIDTHS) + 2 * self.padding, total_height))
        self.contentPanel.revalidate()
        self.contentPanel.repaint()
        self.tablePanel.revalidate()
        self.tablePanel.repaint()

    def update_table_from_last(self):
        if self.last_message:
            self.scan_headers(self.last_message)

    def change_font_size(self, delta):
        self.font_size += delta
        if self.font_size < 10:
            self.font_size = 10
        self.font = Font("Arial", Font.PLAIN, self.font_size)
        self.table_header_font = Font("Arial", Font.BOLD, self.font_size)
        self.site_font = Font("Arial", Font.BOLD, self.font_size)
        self.default_view_font = Font("Arial", Font.PLAIN, self.font_size + 2)
        self.table.setFont(self.font)
        self.table.getTableHeader().setFont(self.table_header_font)
        self.siteLabel.setFont(self.site_font)
        self.table.setRowHeight(self.font_size + DEFAULT_ROW_PADDING)
        self.siteLabel.setPreferredSize(Dimension(sum(DEFAULT_COLUMN_WIDTHS) + 2 * self.padding, self.font_size + 10))
        for cb in self.headerCheckboxes.values():
            cb.setFont(self.font)
        self.zoomIn.setFont(self.font)
        self.zoomOut.setFont(self.font)
        self.defaultView.setFont(self.default_view_font)
        self.clearSelection.setFont(self.font)
        self.exportButton.setFont(self.font)
        self.update_table_size()

    def reset_default_view(self):
        self.font_size = DEFAULT_FONT_SIZE
        self.font = Font("Arial", Font.PLAIN, self.font_size)
        self.table_header_font = Font("Arial", Font.BOLD, self.font_size)
        self.site_font = Font("Arial", Font.BOLD, self.font_size)
        self.default_view_font = Font("Arial", Font.PLAIN, self.font_size + 2)
        self.table.setFont(self.font)
        self.table.getTableHeader().setFont(self.table_header_font)
        self.siteLabel.setFont(self.site_font)
        self.table.setRowHeight(self.font_size + DEFAULT_ROW_PADDING)
        self.siteLabel.setPreferredSize(Dimension(sum(DEFAULT_COLUMN_WIDTHS) + 2 * self.padding, self.font_size + 10))
        for cb in self.headerCheckboxes.values():
            cb.setFont(self.font)
        self.zoomIn.setFont(self.font)
        self.zoomOut.setFont(self.font)
        self.defaultView.setFont(self.default_view_font)
        self.clearSelection.setFont(self.font)
        self.exportButton.setFont(self.font)
        self.reset_column_widths()
        self.reset_column_order()
        self.update_padding(DEFAULT_PADDING)
        self.paddingSlider.setValue(DEFAULT_PADDING)
        self.table.clearSelection()
        self.update_table_size()

    def reset_column_widths(self):
        for i, width in enumerate(DEFAULT_COLUMN_WIDTHS):
            self.table.getColumnModel().getColumn(i).setPreferredWidth(width)

    def reset_column_order(self):
        colModel = self.table.getColumnModel()
        currentCols = [colModel.getColumn(i).getHeaderValue() for i in range(colModel.getColumnCount())]
        valid_headers = [h for h in DEFAULT_ORDER if h in currentCols]
        for targetIndex, colName in enumerate(valid_headers):
            try:
                currentIndex = currentCols.index(colName)
                colModel.moveColumn(currentIndex, targetIndex)
                currentCols.insert(targetIndex, currentCols.pop(currentIndex))
            except ValueError:
                pass

    def update_padding(self, value):
        self.padding = value
        self.paddedPanel.remove(self.leftPadding)
        self.paddedPanel.remove(self.rightPadding)
        self.leftPadding = Box.createHorizontalStrut(self.padding)
        self.rightPadding = Box.createHorizontalStrut(self.padding)
        self.paddedPanel.add(self.leftPadding, BorderLayout.WEST)
        self.paddedPanel.add(self.rightPadding, BorderLayout.EAST)
        self.siteLabel.setPreferredSize(Dimension(sum(DEFAULT_COLUMN_WIDTHS) + 2 * self.padding, self.font_size + 10))
        self.update_table_size()

    # --- Export to PNG ---
    # --- Export to High-Resolution Image ---
    def export_image(self):
        scale = 3.0  # sharper quality

        # Measure components
        site_w = self.table.getColumnModel().getTotalColumnWidth()
        site_h = self.siteLabel.getHeight()
        header_h = self.table.getTableHeader().getHeight()
        table_h = self.table.getRowHeight() * self.table.getRowCount()

        total_w = site_w
        total_h = site_h + header_h + table_h

        # Create image
        img = BufferedImage(int(total_w * scale), int(total_h * scale), BufferedImage.TYPE_INT_ARGB)
        g2 = img.createGraphics()
        g2.scale(scale, scale)

        # White background
        g2.setColor(Color.WHITE)
        g2.fillRect(0, 0, int(total_w * scale), int(total_h * scale))

        # ---- Title (siteLabel) ----
        self.siteLabel.setSize(total_w, site_h)   # force same width as table
        self.siteLabel.paint(g2)

        # ---- Table header ----
        g2.translate(0, site_h)
        self.table.getTableHeader().setSize(total_w, header_h)
        self.table.getTableHeader().paint(g2)

        # ---- Table ----
        g2.translate(0, header_h)
        self.table.setSize(total_w, table_h)
        self.table.paint(g2)

        g2.dispose()

        # Save PNG
        chooser = JFileChooser()
        if chooser.showSaveDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            if not str(file).lower().endswith(".png"):
                file = File(str(file) + ".png")
            ImageIO.write(img, "png", file)




