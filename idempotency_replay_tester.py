"""Idempotency-key and replay tester for Burp's legacy Jython API."""

import hashlib
import hmac
import os
import re
import uuid

from burp import IBurpExtender, ITab, IContextMenuFactory
from java.awt import BorderLayout, FlowLayout
from java.awt.event import ActionListener
from java.lang import System
from java.util import ArrayList
from java.util.concurrent import Callable, Executors
from javax.swing import (
    JButton,
    JCheckBox,
    JComboBox,
    JLabel,
    JMenuItem,
    JOptionPane,
    JPanel,
    JScrollPane,
    JSplitPane,
    SwingWorker,
    JTable,
    JTextArea,
    JTextField,
)
from javax.swing.event import ListSelectionListener
from javax.swing.table import DefaultTableModel


_SCENARIOS = [
    "Same key, parallel identical requests",
    "Missing key, parallel identical requests",
    "Reuse key with changed request",
]
_MIN_SENDS = 2
_MAX_SENDS = 8
_SAFE_KEY = re.compile(r"^[\x21-\x7e]{1,255}$")


class _Action(ActionListener):
    def __init__(self, callback):
        self.callback = callback

    def actionPerformed(self, event):
        self.callback()


class _SelectionListener(ListSelectionListener):
    def __init__(self, callback):
        self.callback = callback

    def valueChanged(self, event):
        self.callback(event)


class _ReadOnlyModel(DefaultTableModel):
    def isCellEditable(self, row, column):
        return False


class _RequestTask(Callable):
    def __init__(self, extension, service, request, number):
        self.extension = extension
        self.service = service
        self.request = request
        self.number = number

    def call(self):
        started = System.nanoTime()
        try:
            exchange = self.extension.callbacks.makeHttpRequest(
                self.service, self.request
            )
            elapsed_ms = (System.nanoTime() - started) / 1000000.0
            response = exchange.getResponse() if exchange is not None else None
            if response is None:
                return {
                    "number": self.number,
                    "status": None,
                    "body_length": 0,
                    "elapsed_ms": elapsed_ms,
                    "body_hash": "",
                    "replayed": "Unknown",
                    "idempotency_status": "",
                    "location_hash": "",
                    "error": "No HTTP response.",
                }
            return self.extension._measure_response(
                self.number, response, elapsed_ms
            )
        except Exception as error:
            elapsed_ms = (System.nanoTime() - started) / 1000000.0
            return {
                "number": self.number,
                "status": None,
                "body_length": 0,
                "elapsed_ms": elapsed_ms,
                "body_hash": "",
                "replayed": "Unknown",
                "idempotency_status": "",
                "location_hash": "",
                "error": str(error),
            }


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.base_service = None
        self.variant_service = None
        self.running = False
        self.results = []
        self.response_hash_key = os.urandom(32)
        callbacks.setExtensionName("Idempotency-key and Replay Tester")
        self._build_ui()
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        callbacks.printOutput("Idempotency-key and Replay Tester loaded")

    def getTabCaption(self):
        return "Idempotency Tester"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return None
        message_info = messages[0]
        items = ArrayList()
        base_item = JMenuItem("Load as idempotency test request")
        base_item.addActionListener(
            _Action(lambda: self._load_message(message_info, False))
        )
        variant_item = JMenuItem("Load as changed-payload reuse request")
        variant_item.addActionListener(
            _Action(lambda: self._load_message(message_info, True))
        )
        items.add(base_item)
        items.add(variant_item)
        return items

    def _build_ui(self):
        self.panel = JPanel(BorderLayout(6, 6))

        controls = JPanel(BorderLayout(4, 4))
        action_row = JPanel(FlowLayout(FlowLayout.LEFT))
        self.run_button = JButton("Run confirmed test")
        self.run_button.addActionListener(_Action(self._run_test))
        self.clear_button = JButton("Clear results")
        self.clear_button.addActionListener(_Action(self._clear_results))
        action_row.add(self.run_button)
        action_row.add(self.clear_button)
        action_row.add(JLabel("Scenario:"))
        self.scenario_box = JComboBox(_SCENARIOS)
        self.scenario_box.addActionListener(_Action(self._scenario_changed))
        action_row.add(self.scenario_box)
        action_row.add(JLabel("Parallel sends:"))
        self.send_count = JTextField("3", 2)
        action_row.add(self.send_count)
        controls.add(action_row, BorderLayout.NORTH)

        key_row = JPanel(FlowLayout(FlowLayout.LEFT))
        key_row.add(JLabel("Idempotency-Key (blank generates a fresh UUID):"))
        self.key_field = JTextField("", 36)
        key_row.add(self.key_field)
        self.confirm_box = JCheckBox(
            "I confirm this may create orders or charge payment methods", False
        )
        key_row.add(self.confirm_box)
        controls.add(key_row, BorderLayout.SOUTH)
        self.panel.add(controls, BorderLayout.NORTH)

        self.base_request = JTextArea(10, 72)
        self.base_request.setLineWrap(False)
        self.variant_request = JTextArea(10, 72)
        self.variant_request.setLineWrap(False)
        base_panel = JPanel(BorderLayout(4, 4))
        base_panel.add(JLabel("Primary request"), BorderLayout.NORTH)
        base_panel.add(JScrollPane(self.base_request), BorderLayout.CENTER)
        variant_panel = JPanel(BorderLayout(4, 4))
        variant_panel.add(JLabel("Changed-payload request for key-reuse scenario"), BorderLayout.NORTH)
        variant_panel.add(JScrollPane(self.variant_request), BorderLayout.CENTER)
        requests_split = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT, base_panel, variant_panel
        )
        requests_split.setResizeWeight(0.5)

        self.result_model = _ReadOnlyModel(
            ["Scenario", "Send", "HTTP", "Body bytes", "Time ms", "Body SHA-256", "Replay signal", "Outcome"],
            0,
        )
        self.result_table = JTable(self.result_model)
        self.result_table.setAutoCreateRowSorter(True)
        self.result_table.getSelectionModel().addListSelectionListener(
            _SelectionListener(self._show_selected_result)
        )
        self.details = JTextArea(5, 80)
        self.details.setEditable(False)
        self.details.setLineWrap(True)
        result_split = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            JScrollPane(self.result_table),
            JScrollPane(self.details),
        )
        result_split.setResizeWeight(0.7)

        result_panel = JPanel(BorderLayout(4, 4))
        result_panel.add(JLabel("Response comparison"), BorderLayout.NORTH)
        result_panel.add(result_split, BorderLayout.CENTER)
        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, requests_split, result_panel)
        main_split.setResizeWeight(0.52)
        self.panel.add(main_split, BorderLayout.CENTER)

        footer = JPanel(BorderLayout())
        self.target_label = JLabel("Request: none")
        self.status_label = JLabel(
            "All scenarios require explicit confirmation. No request is sent automatically."
        )
        footer.add(self.target_label, BorderLayout.NORTH)
        footer.add(self.status_label, BorderLayout.SOUTH)
        self.panel.add(footer, BorderLayout.SOUTH)
        self._scenario_changed()

    def _scenario_changed(self):
        reuse = str(self.scenario_box.getSelectedItem()) == _SCENARIOS[2]
        self.variant_request.setEnabled(reuse)
        self.send_count.setEnabled(not reuse)

    def _load_message(self, message_info, variant):
        request = message_info.getRequest()
        service = message_info.getHttpService()
        if request is None or service is None:
            self.status_label.setText("Selected item has no HTTP request/service.")
            return
        request_text = self.helpers.bytesToString(request)
        request_info = self.helpers.analyzeRequest(service, request)
        method = str(request_info.getMethod()).upper()
        url = request_info.getUrl()
        if variant:
            self.variant_service = service
            self.variant_request.setText(request_text)
            self.status_label.setText("Loaded changed-payload request: %s %s" % (method, url))
        else:
            self.base_service = service
            self.base_request.setText(request_text)
            self.target_label.setText("Request: %s %s" % (method, url))
            self.status_label.setText("Primary request loaded; replay is still disabled until confirmed.")

    def _build_request_with_key(self, service, request, key):
        request_info = self.helpers.analyzeRequest(service, request)
        headers = ArrayList()
        for index, header in enumerate(request_info.getHeaders()):
            header_text = str(header)
            header_name = header_text.split(":", 1)[0].strip().lower()
            if index == 0 or header_name != "idempotency-key":
                headers.add(header_text)
        if key is not None:
            headers.add("Idempotency-Key: " + key)
        body = request[int(request_info.getBodyOffset()):]
        return self.helpers.buildHttpMessage(headers, body)

    def _validate_variant(self, base_service, base_request, variant_service, variant_request):
        if not self._same_service(base_service, variant_service):
            return False, "Primary and changed-payload requests must use the same scheme, host, and port."
        base_info = self.helpers.analyzeRequest(base_service, base_request)
        variant_info = self.helpers.analyzeRequest(variant_service, variant_request)
        base_url = base_info.getUrl()
        variant_url = variant_info.getUrl()
        if str(base_info.getMethod()).upper() != str(variant_info.getMethod()).upper():
            return False, "Both requests must use the same HTTP method."
        if base_url.getPath() != variant_url.getPath():
            return False, "Both requests must use the same URL path."
        base_body = self.helpers.bytesToString(
            base_request[int(base_info.getBodyOffset()):]
        )
        variant_body = self.helpers.bytesToString(
            variant_request[int(variant_info.getBodyOffset()):]
        )
        if base_url.getFile() == variant_url.getFile() and base_body == variant_body:
            return False, "The key-reuse request must have a changed query or body payload."
        return True, ""

    def _same_service(self, first, second):
        return (
            str(first.getProtocol()).lower() == str(second.getProtocol()).lower()
            and str(first.getHost()).lower() == str(second.getHost()).lower()
            and int(first.getPort()) == int(second.getPort())
        )

    def _run_test(self):
        if self.running:
            return
        if self.base_service is None or not self.base_request.getText().strip():
            self.status_label.setText("Load a primary request from Proxy or Repeater first.")
            return
        if not self.confirm_box.isSelected():
            self.status_label.setText("Confirm the potential business side effects before sending requests.")
            return

        scenario = str(self.scenario_box.getSelectedItem())
        base_request = self.helpers.stringToBytes(self.base_request.getText())
        base_service = self.base_service
        base_info = self.helpers.analyzeRequest(base_service, base_request)
        target_url = base_info.getUrl()
        if not self.callbacks.isInScope(target_url):
            self.status_label.setText("Replay blocked: primary target is outside Burp scope.")
            return

        try:
            count = int(self.send_count.getText().strip())
            if not _MIN_SENDS <= count <= _MAX_SENDS:
                raise ValueError("Parallel sends must be between %d and %d." % (_MIN_SENDS, _MAX_SENDS))
        except Exception as error:
            if scenario != _SCENARIOS[2]:
                self.status_label.setText(str(error))
                return
            count = 2

        key = str(self.key_field.getText()).strip()
        generated_key = False
        if scenario == _SCENARIOS[1]:
            key = None
        elif not key:
            key = uuid.uuid4().hex
            generated_key = True
            self.key_field.setText(key)
        if key is not None and not _SAFE_KEY.match(key):
            self.status_label.setText("Use a visible ASCII Idempotency-Key without spaces or control characters.")
            return

        if scenario == _SCENARIOS[2]:
            if self.variant_service is None or not self.variant_request.getText().strip():
                self.status_label.setText("Load a changed-payload request using the context menu first.")
                return
            variant_service = self.variant_service
            variant_request = self.helpers.stringToBytes(self.variant_request.getText())
            valid, reason = self._validate_variant(
                base_service, base_request, variant_service, variant_request
            )
            if not valid:
                self.status_label.setText(reason)
                return
            if not self.callbacks.isInScope(self.helpers.analyzeRequest(variant_service, variant_request).getUrl()):
                self.status_label.setText("Replay blocked: changed-payload target is outside Burp scope.")
                return
        else:
            variant_service = None
            variant_request = None

        send_total = 2 if scenario == _SCENARIOS[2] else count
        answer = JOptionPane.showConfirmDialog(
            self.panel,
            "Send %d request(s) for '%s' to %s? This can create duplicate orders or charges."
            % (send_total, scenario, target_url),
            "Confirm idempotency replay",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE,
        )
        if answer != JOptionPane.YES_OPTION:
            return

        self.running = True
        self._set_controls_enabled(False)
        self.result_model.setRowCount(0)
        self.details.setText("")
        self.status_label.setText("Sending confirmed replay test...")
        extension = self

        class ReplayWorker(SwingWorker):
            def doInBackground(worker_self):
                return extension._execute_scenario(
                    scenario,
                    base_service,
                    base_request,
                    variant_service,
                    variant_request,
                    key,
                    count,
                )

            def done(worker_self):
                extension.running = False
                extension._set_controls_enabled(True)
                try:
                    outcome = worker_self.get()
                    extension._show_results(outcome)
                    if generated_key and extension.key_field.getText().strip() == key:
                        extension.key_field.setText("")
                    extension.status_label.setText(outcome["summary"])
                except Exception as error:
                    extension.status_label.setText("Replay test failed: " + str(error))

        ReplayWorker().execute()

    def _execute_scenario(
        self, scenario, service, base_request, variant_service, variant_request,
        key, count
    ):
        if scenario == _SCENARIOS[0]:
            request = self._build_request_with_key(service, base_request, key)
            results = self._send_parallel(service, request, count)
        elif scenario == _SCENARIOS[1]:
            request = self._build_request_with_key(service, base_request, None)
            results = self._send_parallel(service, request, count)
        else:
            first_request = self._build_request_with_key(service, base_request, key)
            second_request = self._build_request_with_key(
                variant_service, variant_request, key
            )
            results = [self._send_one(service, first_request, 1)]
            results.append(self._send_one(variant_service, second_request, 2))
        return self._summarize(scenario, results)

    def _send_parallel(self, service, request, count):
        executor = Executors.newFixedThreadPool(count)
        futures = []
        try:
            for number in range(1, count + 1):
                futures.append(
                    executor.submit(_RequestTask(self, service, request, number))
                )
            return [future.get() for future in futures]
        finally:
            executor.shutdown()

    def _send_one(self, service, request, number):
        return _RequestTask(self, service, request, number).call()

    def _measure_response(self, number, response, elapsed_ms):
        response_info = self.helpers.analyzeResponse(response)
        headers = {}
        for line in response_info.getHeaders():
            line = str(line)
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            name = name.strip().lower()
            if name in ("idempotency-replayed", "idempotency-status"):
                headers[name] = value.strip()[:80]
            elif name in ("location", "x-request-id"):
                headers[name + "-fingerprint"] = self._fingerprint(value.strip())
        body = response[int(response_info.getBodyOffset()):]
        body_text = self.helpers.bytesToString(body)
        body_hash = self._fingerprint(body_text)
        replayed = headers.get("idempotency-replayed", "Unknown")
        return {
            "number": number,
            "status": int(response_info.getStatusCode()),
            "body_length": len(body),
            "elapsed_ms": elapsed_ms,
            "body_hash": body_hash,
            "replayed": replayed,
            "idempotency_status": headers.get("idempotency-status", ""),
            "location_hash": headers.get("location-sha256", ""),
            "request_id_hash": headers.get("x-request-id-sha256", ""),
            "error": "",
        }

    def _fingerprint(self, value):
        try:
            value_bytes = value.encode("latin-1")
        except Exception:
            value_bytes = str(value).encode("utf-8")
        return hmac.new(
            self.response_hash_key, value_bytes, hashlib.sha256
        ).hexdigest()

    def _summarize(self, scenario, results):
        successful = [
            result for result in results
            if result.get("status") is not None and 200 <= result["status"] < 300
        ]
        unique_success_bodies = set([result["body_hash"] for result in successful])
        replay_signals = [
            result["replayed"] for result in results
            if result.get("replayed", "Unknown").lower() in ("true", "yes", "1")
        ]

        if scenario == _SCENARIOS[0]:
            if replay_signals:
                summary = "Server returned an idempotency replay signal on %d response(s)." % len(replay_signals)
            elif len(successful) > 1 and len(unique_success_bodies) > 1:
                summary = "Potential duplicate action: parallel same-key successes had distinct response bodies. Verify server state."
            elif len(successful) > 1:
                summary = "Multiple same-key requests succeeded with matching response bodies; verify only one action occurred."
            else:
                summary = "No multiple-success idempotency signal observed."
        elif scenario == _SCENARIOS[1]:
            if len(successful) > 1:
                summary = "Potential duplicate action: %d keyless requests succeeded. Verify orders/charges in application state." % len(successful)
            else:
                summary = "No multiple-success keyless replay signal observed."
        else:
            second = results[1] if len(results) > 1 else None
            if second is not None and second.get("status") is not None and 200 <= second["status"] < 300:
                if len(unique_success_bodies) > 1:
                    summary = "Potential key-reuse flaw: changed payload with the same key returned success and a distinct response. Verify state."
                else:
                    summary = "Changed payload with the same key returned success; verify whether it was ignored or applied."
            else:
                summary = "Changed-payload key reuse was not accepted with a 2xx response."

        details = [
            summary,
            "",
            "Response fingerprints are session-keyed HMAC-SHA256 values; response bodies and request credentials are not retained in results.",
            "Response differences cannot prove whether a charge/order was duplicated. Confirm in a safe test environment or authoritative application records.",
        ]
        for result in results:
            details.append(
                "Send %d: Idempotency-Replayed=%s; Idempotency-Status=%s; Location fingerprint=%s; Request-ID fingerprint=%s"
                % (
                    result["number"],
                    result.get("replayed", "Unknown"),
                    result.get("idempotency_status", ""),
                    result.get("location_hash", "")[:16],
                    result.get("request_id_hash", "")[:16],
                )
            )
        rows = []
        for result in results:
            status = str(result["status"]) if result.get("status") is not None else "Error"
            if result.get("error"):
                details.append("Send %d error: %s" % (result["number"], result["error"]))
            rows.append(
                {
                    "scenario": scenario,
                    "number": str(result["number"]),
                    "status": status,
                    "body_length": str(result.get("body_length", "")),
                    "elapsed_ms": "%.1f" % result.get("elapsed_ms", 0.0),
                    "body_hash": result.get("body_hash", ""),
                    "replayed": result.get("replayed", "Unknown"),
                    "outcome": (
                        "2xx success"
                        if result.get("status") is not None and 200 <= result["status"] < 300
                        else result.get("error") or "Non-2xx response"
                    ),
                    "details": "\n".join(details),
                }
            )
        return {"summary": summary, "details": "\n".join(details), "rows": rows}

    def _show_results(self, outcome):
        self.results = outcome["rows"]
        self.result_model.setRowCount(0)
        for result in self.results:
            self.result_model.addRow(
                [
                    result["scenario"],
                    result["number"],
                    result["status"],
                    result["body_length"],
                    result["elapsed_ms"],
                    result["body_hash"][:16],
                    result["replayed"],
                    result["outcome"],
                ]
            )
        self.details.setText(outcome["details"])

    def _show_selected_result(self, event):
        if event.getValueIsAdjusting():
            return
        row = self.result_table.getSelectedRow()
        if row < 0:
            return
        model_row = self.result_table.convertRowIndexToModel(row)
        if model_row < len(self.results):
            result = self.results[model_row]
            self.details.setText(
                result["details"]
                + "\n\nSend %s: HTTP %s, %s bytes, %.1f ms, SHA-256 %s"
                % (
                    result["number"],
                    result["status"],
                    result["body_length"],
                    float(result["elapsed_ms"]),
                    result["body_hash"],
                )
            )

    def _set_controls_enabled(self, enabled):
        self.run_button.setEnabled(enabled)
        self.clear_button.setEnabled(enabled)
        self.scenario_box.setEnabled(enabled)
        self.send_count.setEnabled(enabled and self.scenario_box.getSelectedItem() != _SCENARIOS[2])
        self.key_field.setEnabled(enabled)
        self.confirm_box.setEnabled(enabled)
        self.base_request.setEnabled(enabled)
        self.variant_request.setEnabled(enabled and self.scenario_box.getSelectedItem() == _SCENARIOS[2])

    def _clear_results(self):
        if self.running:
            return
        self.results = []
        self.result_model.setRowCount(0)
        self.details.setText("")
        self.status_label.setText("Results cleared; captured request text remains in memory.")