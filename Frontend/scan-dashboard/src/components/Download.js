import { useState } from "react";

import { downloadExport } from "../api";
import { triggerDownload } from "../utils/exportBuilders";

const localFormats = [
  { key: "json-raw", label: "JSON (Raw)" },
  { key: "pdf", label: "PDF" },
  { key: "doc", label: "DOC" },
  { key: "ppt", label: "PPT" },
  { key: "excel", label: "Excel" },
  { key: "markdown", label: "Markdown" },
  { key: "text", label: "Text" },
];

const extensionMap = {
  "json-raw": "json",
  pdf: "pdf",
  doc: "docx",
  ppt: "pptx",
  excel: "xlsx",
  markdown: "md",
  text: "txt",
};

export default function Download({ context, jobId }) {
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");

  if (!context || !jobId) return null;

  const handleDownload = async (format) => {
    setBusy(format.key);
    setMessage("");
    try {
      const exportFormat = format.key === "json-raw" ? "json" : format.key;
      const response = await downloadExport(jobId, exportFormat);
      const fallbackName = format.key === "json-raw"
        ? `scan_report_${jobId}.json`
        : `scan_report_${jobId}.${extensionMap[format.key] || format.key}`;
      triggerDownload(
        response.filename || fallbackName,
        response.blob,
        response.contentType
      );
      setMessage(`${format.label} export downloaded.`);
    } catch (error) {
      setMessage(error.message || "Export failed.");
    } finally {
      setBusy("");
    }
  };

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <h2>Exports</h2>
          <p>Raw API export plus contextual stakeholder-ready reporting formats built from the shared report context.</p>
        </div>
      </div>
      <div className="download-actions">
        {localFormats.map((format) => (
          <button
            className="secondary-action"
            key={format.key}
            disabled={Boolean(busy)}
            onClick={() => handleDownload(format)}
            type="button"
          >
            {busy === format.key ? "Preparing..." : format.label}
          </button>
        ))}
      </div>
      {message ? <p className="review-note">{message}</p> : null}
    </section>
  );
}
