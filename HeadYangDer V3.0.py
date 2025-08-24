# --------- HeadYangDer          ---------
# --------- Burp Suite Extension ---------
# --------- V3 (History&Design)  ---------
# --------- XD                   ---------
# --------- GL                   ---------
# --------- TQ                   ---------
# --------- Born at 22/8/2025    ---------

# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IContextMenuFactory
from javax.swing import JPanel, JTable, JScrollPane, JMenuItem, JButton, JCheckBox, BoxLayout, Box, JSlider, JLabel, BorderFactory, JFileChooser, JDialog, JSplitPane, SwingUtilities
from java.awt import BorderLayout, Font, Dimension, Color
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.imageio import ImageIO
from java.awt.image import BufferedImage
import java.io.File as File
import re

# --- Theme Colors ---
DARK_BLUE = Color(0x17, 0x35, 0x51)
LIGHT_GREY = Color(0xF0F0F0)
MID_GREY = Color(0xD0D0D0)
WHITE = Color.WHITE
TEXT_DARK_BLUE = DARK_BLUE

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
        comp.setBackground(WHITE if row % 2 == 0 else LIGHT_GREY)  # Zebra striping
        # Add padding to the cell (left, top, right, bottom)
        comp.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(MID_GREY, 1),  # Existing outline
            BorderFactory.createEmptyBorder(5, 10, 5, 10)  # Add padding: 10px left/right, 5px top/bottom
        ))
        if column == 1:  # Status column
            if value == "OK":
                comp.setForeground(Color(0, 128, 0))
            elif value == "Missing":
                comp.setForeground(Color.RED)
            elif value == "Incorrect":
                comp.setForeground(Color.ORANGE)
            else:
                comp.setForeground(TEXT_DARK_BLUE)
        else:
            comp.setForeground(TEXT_DARK_BLUE)
        return comp

class HistoryCellRenderer(DefaultTableCellRenderer):
    def __init__(self, extender):
        self.extender = extender
        super(HistoryCellRenderer, self).__init__()

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        comp = super(HistoryCellRenderer, self).getTableCellRendererComponent(
            table, value, isSelected, hasFocus, row, column
        )
        modelRow = table.convertRowIndexToModel(row)
        if isSelected:
            comp.setBackground(table.getSelectionBackground())
            comp.setForeground(table.getSelectionForeground())
        else:
            if modelRow == self.extender.currentHistoryRow:
                comp.setBackground(Color(200, 230, 255))  # light blue highlight for loaded row
                comp.setForeground(Color.BLACK)
            else:
                comp.setBackground(table.getBackground())
                comp.setForeground(table.getForeground())
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

        # History storage
        self.history = []
        self.historyModel = DefaultTableModel(["#", "Host", "URL", "Timestamp"], 0)
        self.historyTable = JTable(self.historyModel)
        self.requestViewer = self.callbacks.createMessageEditor(None, False)
        self.responseViewer = self.callbacks.createMessageEditor(None, False)

        from javax.swing import JPopupMenu, JMenuItem

        # Create popup menu
        popupMenu = JPopupMenu()

        deleteItem = JMenuItem("Delete", actionPerformed=self.delete_history_item)
        popupMenu.add(deleteItem)

        # Attach popup menu to historyTable
        self.historyTable.setComponentPopupMenu(popupMenu)

        from javax.swing.table import TableRowSorter

        # Enable sorting
        sorter = TableRowSorter(self.historyModel)
        self.historyTable.setRowSorter(sorter)

        # Highlight selected row
        self.currentHistoryRow = -1

        # Apply the custom renderer to all columns
        renderer = HistoryCellRenderer(self)
        for i in range(self.historyTable.getColumnCount()):
            self.historyTable.getColumnModel().getColumn(i).setCellRenderer(renderer)

        # Resize number column
        self.historyTable.getColumnModel().getColumn(0).setPreferredWidth(50)
        self.historyTable.getColumnModel().getColumn(0).setMaxWidth(60)

        # --- UI Panel ---
        self.panel = JPanel(BorderLayout())
        self.panel.setBackground(LIGHT_GREY)

        # Left panel: checkboxes with theme
        self.checkboxPanel = JPanel()
        self.checkboxPanel.setLayout(BoxLayout(self.checkboxPanel, BoxLayout.Y_AXIS))
        self.checkboxPanel.setBackground(MID_GREY)
        self.checkboxPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20))  # Padding around panel
        self.headerCheckboxes = {}
        for h in DEFAULT_ORDER:
            cb = JCheckBox(h, True)
            cb.setFont(self.font)
            cb.setForeground(TEXT_DARK_BLUE)
            cb.setBackground(MID_GREY)
            cb.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))  # Padding per checkbox
            cb.addActionListener(lambda e, hn=h: self.update_table_from_last())
            self.checkboxPanel.add(cb)
            self.headerCheckboxes[h] = cb
        self.panel.add(self.checkboxPanel, BorderLayout.WEST)

        # Center panel
        self.tablePanel = JPanel(BorderLayout())
        self.tablePanel.setBackground(WHITE)
        self.contentPanel = JPanel(BorderLayout())
        self.contentPanel.setBackground(WHITE)
        self.tablePanel.add(self.contentPanel, BorderLayout.CENTER)

        self.paddedPanel = JPanel(BorderLayout())
        self.paddedPanel.setBackground(WHITE)
        self.paddedPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, DEFAULT_BOTTOM_SPACE, 0))
        self.leftPadding = Box.createHorizontalStrut(self.padding)
        self.rightPadding = Box.createHorizontalStrut(self.padding)
        self.paddedPanel.add(self.leftPadding, BorderLayout.WEST)
        self.paddedPanel.add(self.rightPadding, BorderLayout.EAST)

        # Site label (banner)
        self.siteLabel = JLabel("No request scanned yet")
        self.siteLabel.setFont(self.site_font)
        self.siteLabel.setForeground(Color.BLACK)  # Default black text
        self.siteLabel.setOpaque(False)  # Transparent background
        self.siteLabel.setHorizontalAlignment(JLabel.CENTER)
        self.siteLabel.setBorder(BorderFactory.createEmptyBorder(10, 0, 10, 0))  # Vertical padding
        self.siteLabel.setPreferredSize(Dimension(sum(DEFAULT_COLUMN_WIDTHS) + 2 * self.padding, self.font_size + 20))
        self.tablePanel.add(self.siteLabel, BorderLayout.NORTH)

        # Main table
        self.model = DefaultTableModel(["Header", "Status", "Details"], 0)
        self.table = JTable(self.model)
        self.table.getTableHeader().setReorderingAllowed(True)
        self.table.getTableHeader().setFont(self.table_header_font)
        self.table.getTableHeader().setBackground(DARK_BLUE)
        self.table.getTableHeader().setForeground(WHITE)
        self.table.setFont(self.font)
        self.table.setRowHeight(self.font_size + DEFAULT_ROW_PADDING)
        self.table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self.table.setBackground(WHITE)
        self.table.setForeground(TEXT_DARK_BLUE)
        self.table.setGridColor(MID_GREY)
        self.table.setShowGrid(True)  # Enable grid lines

        self.table.getColumnModel().getColumn(0).setCellRenderer(StatusCellRenderer())
        self.table.getColumnModel().getColumn(1).setCellRenderer(StatusCellRenderer())
        self.table.getColumnModel().getColumn(2).setCellRenderer(StatusCellRenderer())

        # No scrollbars
        self.scrollPane = JScrollPane(self.table,
                                      JScrollPane.VERTICAL_SCROLLBAR_NEVER,
                                      JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        self.scrollPane.setBackground(WHITE)
        self.paddedPanel.add(self.scrollPane, BorderLayout.CENTER)
        self.contentPanel.add(self.paddedPanel, BorderLayout.NORTH)

        self.panel.add(self.tablePanel, BorderLayout.CENTER)

        # Top panel: controls
        self.topPanel = JPanel()
        self.topPanel.setBackground(LIGHT_GREY)
        self.zoomIn = JButton("Zoom +", actionPerformed=lambda e: self.change_font_size(2))
        self.zoomIn.setFont(self.font)
        self.zoomIn.setForeground(TEXT_DARK_BLUE)
        self.zoomIn.setOpaque(False)  # No background color
        self.zoomIn.setContentAreaFilled(False)
        self.zoomIn.setBorderPainted(True)
        self.zoomOut = JButton("Zoom -", actionPerformed=lambda e: self.change_font_size(-2))
        self.zoomOut.setFont(self.font)
        self.zoomOut.setForeground(TEXT_DARK_BLUE)
        self.zoomOut.setOpaque(False)  # No background color
        self.zoomOut.setContentAreaFilled(False)
        self.zoomOut.setBorderPainted(True)
        self.defaultView = JButton("Default View", actionPerformed=lambda e: self.reset_default_view())
        self.defaultView.setFont(self.default_view_font)
        self.defaultView.setForeground(TEXT_DARK_BLUE)
        self.defaultView.setOpaque(False)  # No background color
        self.defaultView.setContentAreaFilled(False)
        self.defaultView.setBorderPainted(True)
        self.clearSelection = JButton("Clear Selection", actionPerformed=lambda e: self.table.clearSelection())
        self.clearSelection.setFont(self.font)
        self.clearSelection.setForeground(TEXT_DARK_BLUE)
        self.clearSelection.setOpaque(False)  # No background color
        self.clearSelection.setContentAreaFilled(False)
        self.clearSelection.setBorderPainted(True)
        self.exportButton = JButton("Export Image", actionPerformed=lambda e: self.export_image())
        self.exportButton.setFont(self.font)
        self.exportButton.setForeground(TEXT_DARK_BLUE)
        self.exportButton.setOpaque(False)  # No background color
        self.exportButton.setContentAreaFilled(False)
        self.exportButton.setBorderPainted(True)

        self.topPanel.add(self.zoomIn)
        self.topPanel.add(self.zoomOut)
        self.topPanel.add(self.defaultView)
        self.topPanel.add(self.clearSelection)
        self.topPanel.add(self.exportButton)

        paddingLabel = JLabel("Padding:")
        paddingLabel.setForeground(TEXT_DARK_BLUE)
        self.topPanel.add(paddingLabel)
        self.paddingSlider = JSlider(0, 100, self.padding)
        self.paddingSlider.setPreferredSize(Dimension(120, 40))
        self.paddingSlider.addChangeListener(lambda e: self.update_padding(self.paddingSlider.getValue()))
        self.topPanel.add(self.paddingSlider)

        self.panel.add(self.topPanel, BorderLayout.NORTH)

        # --- History Button at bottom ---
        self.historyButton = JButton("View History", actionPerformed=lambda e: self.show_history_dialog())
        self.historyButton.setFont(self.font)
        self.historyButton.setForeground(TEXT_DARK_BLUE)
        self.historyButton.setOpaque(False)  # No background color
        self.historyButton.setContentAreaFilled(False)
        self.historyButton.setBorderPainted(True)
        self.panel.add(self.historyButton, BorderLayout.SOUTH)

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
    def scan_headers(self, message, add_to_history=True):
        self.last_message = message
        self.model.setRowCount(0)

        if message:
            request_info = self.helpers.analyzeRequest(message)
            url = request_info.getUrl()
            host = url.getHost()
            full_url = url.toString()
            self.siteLabel.setText("%s (%s)" % (host, full_url))
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

        # --- Save to History only if new scan ---
        if add_to_history:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.history.append((host, full_url, message, timestamp))
            row_number = self.historyTable.getRowCount() + 1
            self.historyModel.addRow([row_number, host, full_url, timestamp])

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
            self.scan_headers(self.last_message, add_to_history=False)

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
        self.siteLabel.setPreferredSize(Dimension(sum(DEFAULT_COLUMN_WIDTHS) + 2 * self.padding, self.font_size + 20))
        for cb in self.headerCheckboxes.values():
            cb.setFont(self.font)
            cb.setForeground(TEXT_DARK_BLUE)
        self.zoomIn.setFont(self.font)
        self.zoomIn.setForeground(TEXT_DARK_BLUE)
        self.zoomOut.setFont(self.font)
        self.zoomOut.setForeground(TEXT_DARK_BLUE)
        self.defaultView.setFont(self.default_view_font)
        self.defaultView.setForeground(TEXT_DARK_BLUE)
        self.clearSelection.setFont(self.font)
        self.clearSelection.setForeground(TEXT_DARK_BLUE)
        self.exportButton.setFont(self.font)
        self.exportButton.setForeground(TEXT_DARK_BLUE)
        self.historyButton.setFont(self.font)
        self.historyButton.setForeground(TEXT_DARK_BLUE)
        self.update_table_size()

    def reset_default_view(self):
        self.font_size = DEFAULT_FONT_SIZE
        self.font = Font("Arial", Font.PLAIN, self.font_size)
        self.table_header_font = Font("Arial", Font.BOLD, self.font_size)
        self.site_font = Font("Arial", Font.BOLD, self.font_size)
        self.default_view_font = Font("Arial", Font.PLAIN, self.font_size + 2)
        self.table.setFont(self.font)
        self.table.getTableHeader().setFont(self.table_header_font)
        self.table.getTableHeader().setBackground(DARK_BLUE)
        self.table.getTableHeader().setForeground(WHITE)
        self.table.setBackground(WHITE)
        self.table.setForeground(TEXT_DARK_BLUE)
        self.table.setGridColor(MID_GREY)
        self.table.setShowGrid(True)
        self.siteLabel.setFont(self.site_font)
        self.siteLabel.setForeground(Color.BLACK)
        self.siteLabel.setOpaque(False)
        self.table.setRowHeight(self.font_size + DEFAULT_ROW_PADDING)
        self.siteLabel.setPreferredSize(Dimension(sum(DEFAULT_COLUMN_WIDTHS) + 2 * self.padding, self.font_size + 20))
        for cb in self.headerCheckboxes.values():
            cb.setFont(self.font)
            cb.setForeground(TEXT_DARK_BLUE)
            cb.setBackground(MID_GREY)
        self.zoomIn.setFont(self.font)
        self.zoomIn.setForeground(TEXT_DARK_BLUE)
        self.zoomIn.setOpaque(False)
        self.zoomIn.setContentAreaFilled(False)
        self.zoomIn.setBorderPainted(True)
        self.zoomOut.setFont(self.font)
        self.zoomOut.setForeground(TEXT_DARK_BLUE)
        self.zoomOut.setOpaque(False)
        self.zoomOut.setContentAreaFilled(False)
        self.zoomOut.setBorderPainted(True)
        self.defaultView.setFont(self.default_view_font)
        self.defaultView.setForeground(TEXT_DARK_BLUE)
        self.defaultView.setOpaque(False)
        self.defaultView.setContentAreaFilled(False)
        self.defaultView.setBorderPainted(True)
        self.clearSelection.setFont(self.font)
        self.clearSelection.setForeground(TEXT_DARK_BLUE)
        self.clearSelection.setOpaque(False)
        self.clearSelection.setContentAreaFilled(False)
        self.clearSelection.setBorderPainted(True)
        self.exportButton.setFont(self.font)
        self.exportButton.setForeground(TEXT_DARK_BLUE)
        self.exportButton.setOpaque(False)
        self.exportButton.setContentAreaFilled(False)
        self.exportButton.setBorderPainted(True)
        self.historyButton.setFont(self.font)
        self.historyButton.setForeground(TEXT_DARK_BLUE)
        self.historyButton.setOpaque(False)
        self.historyButton.setContentAreaFilled(False)
        self.historyButton.setBorderPainted(True)
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
        self.siteLabel.setPreferredSize(Dimension(sum(DEFAULT_COLUMN_WIDTHS) + 2 * self.padding, self.font_size + 20))
        self.update_table_size()

    # --- Export to PNG ---
    def export_image(self):
        scale = 3.0  # sharper quality

        # Measure components
        site_w = self.table.getColumnModel().getTotalColumnWidth()
        site_h = self.siteLabel.getPreferredSize().height
        header_h = self.table.getTableHeader().getPreferredSize().height
        table_h = self.table.getRowHeight() * self.table.getRowCount()

        total_w = site_w
        total_h = site_h + header_h + table_h

        # Create image
        img = BufferedImage(int(total_w * scale), int(total_h * scale), BufferedImage.TYPE_INT_ARGB)
        g2 = img.createGraphics()
        g2.scale(scale, scale)

        # White background
        g2.setColor(WHITE)
        g2.fillRect(0, 0, total_w, total_h)

        # ---- Title (siteLabel) ----
        self.siteLabel.setSize(total_w, site_h)   # force same width as table
        self.siteLabel.paint(g2)

        # ---- Draw outline between siteLabel and table header ----
        g2.setColor(MID_GREY)
        g2.drawLine(0, site_h, total_w, site_h)

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

    # --- History Management ---
    def renumber_history(self):
        for i in range(self.historyModel.getRowCount()):
            self.historyModel.setValueAt(i + 1, i, 0)

    def show_history_dialog(self):
        dialog = JDialog(SwingUtilities.getWindowAncestor(self.panel), "Scan History", True)
        dialog.setLayout(BorderLayout())
        dialog.setSize(1200, 750)  # Wider dialog

        # Left = history table
        historyScroll = JScrollPane(self.historyTable)
        historyScroll.setPreferredSize(Dimension(450, 650))

        # Right = request/response split
        split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                           self.requestViewer.getComponent(),
                           self.responseViewer.getComponent())
        split.setDividerLocation(350)  # Adjusted for better request/response view

        mainPanel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, historyScroll, split)
        mainPanel.setDividerLocation(400)  # Wider history table area
        dialog.add(mainPanel, BorderLayout.CENTER)

        # Bottom buttons
        btnPanel = JPanel()
        loadBtn = JButton("Load Result", actionPerformed=lambda e: self.load_history_item())
        closeBtn = JButton("Close", actionPerformed=lambda e: dialog.dispose())
        btnPanel.add(loadBtn)
        btnPanel.add(closeBtn)
        dialog.add(btnPanel, BorderLayout.SOUTH)

        # Row selection = preview only
        self.historyTable.getSelectionModel().addListSelectionListener(
            lambda e: self.preview_history_item()
        )

        # Resize number column
        self.historyTable.getColumnModel().getColumn(0).setPreferredWidth(50)
        self.historyTable.getColumnModel().getColumn(0).setMaxWidth(60)

        dialog.setVisible(True)

    def preview_history_item(self):
        row = self.historyTable.getSelectedRow()
        if row >= 0:
            modelRow = self.historyTable.convertRowIndexToModel(row)
            _, _, message, _ = self.history[modelRow]  # ignore timestamp here
            self.requestViewer.setMessage(message.getRequest(), True)
            self.responseViewer.setMessage(message.getResponse(), False)

    def load_history_item(self):
        row = self.historyTable.getSelectedRow()
        if row >= 0:
            modelRow = self.historyTable.convertRowIndexToModel(row)
            _, _, message, _ = self.history[modelRow]
            self.currentHistoryRow = modelRow
            self.scan_headers(message, add_to_history=False)  # Don't append again
            self.historyTable.repaint()  # Refresh highlight

    def delete_history_item(self, event):
        row = self.historyTable.getSelectedRow()
        if row >= 0:
            modelRow = self.historyTable.convertRowIndexToModel(row)

            # Remove from history list + table
            self.history.pop(modelRow)
            self.historyModel.removeRow(modelRow)

            # Reset highlight if needed
            if self.currentHistoryRow == modelRow:
                self.currentHistoryRow = -1
            elif self.currentHistoryRow > modelRow:
                self.currentHistoryRow -= 1

            # Renumber rows
            self.renumber_history()
            self.historyTable.repaint()