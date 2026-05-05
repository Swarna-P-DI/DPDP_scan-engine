from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Iterable

import pandas as pd
import plotly.graph_objects as go

try:
    from dash import Dash, Input, Output, dcc, html
except ImportError:  # pragma: no cover - Dash is an optional runtime dependency.
    Dash = None
    Input = None
    Output = None
    dcc = None
    html = None


CellMetadata = Mapping[str, Any] | pd.DataFrame | None


def prepare_numeric_matrix(
    matrix: pd.DataFrame,
    *,
    fill_value: float = 0.0,
    drop_empty: bool = True,
) -> pd.DataFrame:
    if not isinstance(matrix, pd.DataFrame):
        matrix = pd.DataFrame(matrix)

    numeric = matrix.apply(pd.to_numeric, errors="coerce")
    if drop_empty:
        numeric = numeric.dropna(axis=0, how="all").dropna(axis=1, how="all")
    numeric = numeric.fillna(fill_value)

    if numeric.empty:
        return pd.DataFrame([[fill_value]], index=["No data"], columns=["No data"])

    numeric.index = [str(index) for index in numeric.index]
    numeric.columns = [str(column) for column in numeric.columns]
    return numeric


def build_plotly_heatmap(
    matrix: pd.DataFrame,
    *,
    metadata: CellMetadata = None,
    dataset_name: str = "Unknown dataset",
    title: str = "Data Similarity Heatmap",
    fill_value: float = 0.0,
    selected_cell: tuple[str, str] | None = None,
) -> go.Figure:
    numeric = prepare_numeric_matrix(matrix, fill_value=fill_value)
    customdata = _build_customdata(numeric, metadata, dataset_name)

    figure = go.Figure(
        data=[
            go.Heatmap(
                z=numeric.values,
                x=list(numeric.columns),
                y=list(numeric.index),
                customdata=customdata,
                colorscale="YlOrRd",
                colorbar={
                    "title": "Risk Score",
                    "tickmode": "array",
                    "tickvals": [0, 1, 2, 3],
                    "ticktext": ["Low", "Low", "Medium", "High"],
                },
                hovertemplate=(
                    "<b>%{y}</b><br>"
                    "Column: %{x}<br>"
                    "Value: %{z}<br>"
                    "Dataset: %{customdata[3]}<br>"
                    "PII Type: %{customdata[4]}<br>"
                    "Risk Score: %{customdata[5]}<br>"
                    "Sample: %{customdata[6]}"
                    "<extra></extra>"
                ),
            )
        ]
    )

    if selected_cell:
        row_label, column_label = selected_cell
        figure.add_trace(
            go.Scatter(
                x=[column_label],
                y=[row_label],
                mode="markers",
                marker={
                    "symbol": "square-open",
                    "size": 34,
                    "color": "#162635",
                    "line": {"width": 3},
                },
                hoverinfo="skip",
                showlegend=False,
            )
        )

    figure.update_layout(
        title={"text": title, "x": 0.02, "xanchor": "left"},
        autosize=True,
        margin={"l": 95, "r": 30, "t": 70, "b": 110},
        paper_bgcolor="#fbfcfd",
        plot_bgcolor="#fbfcfd",
        font={"family": "Aptos, Segoe UI, sans-serif", "color": "#162635"},
        dragmode="zoom",
    )
    figure.update_xaxes(tickangle=-45, automargin=True, title="")
    figure.update_yaxes(automargin=True, title="", autorange="reversed")
    return figure


def plot_clustered_heatmap(
    matrix: pd.DataFrame,
    output_path: str | Path | None = None,
    *,
    title: str = "Data Similarity Heatmap",
    metadata: CellMetadata = None,
    dataset_name: str = "Unknown dataset",
    fill_value: float = 0.0,
    **_: Any,
) -> go.Figure:
    """Build a Plotly heatmap and optionally write it as interactive HTML.

    The historical name is kept for existing imports, but the implementation is
    now click-ready Plotly rather than a static seaborn/matplotlib chart.
    """
    figure = build_plotly_heatmap(
        matrix,
        metadata=metadata,
        dataset_name=dataset_name,
        title=title,
        fill_value=fill_value,
    )

    if output_path:
        path = Path(output_path)
        if path.suffix.lower() != ".html":
            path = path.with_suffix(".html")
        path.parent.mkdir(parents=True, exist_ok=True)
        figure.write_html(path, include_plotlyjs="cdn", full_html=True)

    return figure


class InteractiveHeatmap:
    def __init__(
        self,
        matrix: pd.DataFrame,
        *,
        metadata: CellMetadata = None,
        dataset_name: str = "Unknown dataset",
        title: str = "Data Similarity Heatmap",
        fill_value: float = 0.0,
    ) -> None:
        self.matrix = prepare_numeric_matrix(matrix, fill_value=fill_value)
        self.metadata = metadata
        self.dataset_name = dataset_name
        self.title = title
        self.fill_value = fill_value

    def figure(self, selected_cell: tuple[str, str] | None = None) -> go.Figure:
        return build_plotly_heatmap(
            self.matrix,
            metadata=self.metadata,
            dataset_name=self.dataset_name,
            title=self.title,
            fill_value=self.fill_value,
            selected_cell=selected_cell,
        )

    def panel(self, click_data: dict[str, Any] | None) -> Any:
        return build_info_panel(click_data)

    def dash_layout(self) -> Any:
        _require_dash()
        return html.Div(
            className="heatmap-shell",
            children=[
                html.Div(
                    className="heatmap-main",
                    children=[
                        dcc.Graph(
                            id="data-similarity-heatmap",
                            figure=self.figure(),
                            config={
                                "displaylogo": False,
                                "responsive": True,
                                "scrollZoom": True,
                                "modeBarButtonsToRemove": ["lasso2d", "select2d"],
                            },
                            style={"height": "72vh", "minHeight": "520px"},
                        )
                    ],
                ),
                html.Aside(
                    id="heatmap-info-panel",
                    className="heatmap-info-panel",
                    children=empty_info_panel(),
                ),
            ],
        )


def create_dash_heatmap_app(
    matrix: pd.DataFrame,
    *,
    metadata: CellMetadata = None,
    dataset_name: str = "Unknown dataset",
    title: str = "Data Similarity Heatmap",
) -> Any:
    _require_dash()
    heatmap = InteractiveHeatmap(
        matrix,
        metadata=metadata,
        dataset_name=dataset_name,
        title=title,
    )
    app = Dash(__name__)
    app.title = title
    app.layout = html.Div(
        children=[
            dcc.Store(id="selected-heatmap-cell"),
            heatmap.dash_layout(),
        ],
        style={"minHeight": "100vh", "background": "#eef3f6", "padding": "18px"},
    )

    app.index_string = _dash_index_template(title)

    @app.callback(
        Output("heatmap-info-panel", "children"),
        Output("data-similarity-heatmap", "figure"),
        Input("data-similarity-heatmap", "clickData"),
    )
    def update_info_panel(click_data: dict[str, Any] | None) -> tuple[Any, go.Figure]:
        selected = _selected_cell(click_data)
        return heatmap.panel(click_data), heatmap.figure(selected_cell=selected)

    return app


def build_info_panel(click_data: dict[str, Any] | None) -> Any:
    _require_dash()
    if not click_data:
        return empty_info_panel()

    point = (click_data.get("points") or [{}])[0]
    cell = _cell_payload(point)
    extra_metadata = cell.get("metadata") or {}
    metadata_items = [
        html.Div(
            className="metadata-row",
            children=[html.Span(str(key)), html.Strong(_format_value(value))],
        )
        for key, value in extra_metadata.items()
        if key not in {"pii_type", "risk_score", "sample_data", "sample", "source", "dataset_name"}
    ]

    return html.Div(
        className="info-card",
        children=[
            html.P("Selected Cell", className="info-eyebrow"),
            html.H2(f"{cell['row_label']} / {cell['column_label']}"),
            html.Div(
                className="info-grid",
                children=[
                    _info_metric("Column Name", cell["column_label"]),
                    _info_metric("Table / Dataset Name", cell["dataset_name"]),
                    _info_metric("PII Type", cell["pii_type"]),
                    _info_metric("Risk Score", cell["risk_score"]),
                    _info_metric("Sample Data", cell["sample_data"]),
                    _info_metric("Cell Value", cell["value"]),
                ],
            ),
            html.H3("Metadata"),
            html.Div(metadata_items or [html.P("No additional metadata for this cell.", className="muted")]),
        ],
    )


def empty_info_panel() -> Any:
    _require_dash()
    return html.Div(
        className="info-card empty",
        children=[
            html.P("Data Similarity Heatmap", className="info-eyebrow"),
            html.H2("Select a cell"),
            html.P("Click any heatmap cell to inspect row, column, risk score, PII details, masked sample data, and attached metadata."),
        ],
    )


def pii_source_matrix(pii_findings: Iterable[dict[str, Any]]) -> pd.DataFrame:
    rows: dict[str, dict[str, float]] = {}
    for finding in pii_findings or []:
        source = str(finding.get("table") or finding.get("source_id") or "unknown")
        pii_type = str(finding.get("pii_type") or finding.get("piiType") or "unknown").upper()
        risk_label = str(finding.get("risk") or "").lower()
        masking = str(finding.get("masking") or "").lower()
        score = _risk_score(risk_label, masking)
        rows.setdefault(source, {})
        rows[source][pii_type] = max(rows[source].get(pii_type, 0.0), score)

    if not rows:
        return pd.DataFrame([[0.0]], index=["No PII"], columns=["No PII"])
    return pd.DataFrame.from_dict(rows, orient="index").fillna(0.0)


def metadata_from_pii_findings(pii_findings: Iterable[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    metadata: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in pii_findings or []:
        source = str(finding.get("table") or finding.get("source_id") or "unknown")
        pii_type = str(finding.get("pii_type") or finding.get("piiType") or "unknown").upper()
        sample = finding.get("sample_data") or finding.get("sample") or finding.get("evidence") or "N/A"
        metadata[(source, pii_type)] = {
            "column_name": finding.get("column") or pii_type,
            "dataset_name": source,
            "pii_type": pii_type,
            "risk_score": _risk_score(str(finding.get("risk") or "").lower(), str(finding.get("masking") or "").lower()),
            "sample_data": _mask_sample(sample),
            "source": finding.get("source") or source,
            "masking": finding.get("masking"),
            "risk": finding.get("risk"),
        }
    return metadata


def _build_customdata(matrix: pd.DataFrame, metadata: CellMetadata, dataset_name: str) -> list[list[list[Any]]]:
    rows: list[list[list[Any]]] = []
    for row_label in matrix.index:
        row_values: list[list[Any]] = []
        for column_label in matrix.columns:
            value = matrix.loc[row_label, column_label]
            cell_metadata = _metadata_for_cell(metadata, row_label, column_label)
            sample_data = _mask_sample(cell_metadata.get("sample_data") or cell_metadata.get("sample") or "N/A")
            risk_score = cell_metadata.get("risk_score", value)
            row_values.append(
                [
                    row_label,
                    column_label,
                    float(value),
                    cell_metadata.get("dataset_name") or cell_metadata.get("table") or dataset_name,
                    cell_metadata.get("pii_type") or cell_metadata.get("piiType") or column_label,
                    risk_score,
                    sample_data,
                    json.dumps(cell_metadata, default=str),
                ]
            )
        rows.append(row_values)
    return rows


def _metadata_for_cell(metadata: CellMetadata, row_label: str, column_label: str) -> dict[str, Any]:
    if metadata is None:
        return {}
    if isinstance(metadata, pd.DataFrame):
        if row_label in metadata.index and column_label in metadata.columns:
            value = metadata.loc[row_label, column_label]
            return value if isinstance(value, dict) else {"metadata": value}
        return {}
    for key in ((row_label, column_label), f"{row_label}|{column_label}", f"{row_label}.{column_label}", column_label):
        value = metadata.get(key) if isinstance(metadata, Mapping) else None
        if isinstance(value, dict):
            return dict(value)
    return {}


def _cell_payload(point: dict[str, Any]) -> dict[str, Any]:
    customdata = point.get("customdata") or []
    metadata = {}
    if len(customdata) > 7:
        try:
            metadata = json.loads(customdata[7] or "{}")
        except json.JSONDecodeError:
            metadata = {"raw_metadata": customdata[7]}
    return {
        "row_label": customdata[0] if len(customdata) > 0 else point.get("y", "N/A"),
        "column_label": customdata[1] if len(customdata) > 1 else point.get("x", "N/A"),
        "value": customdata[2] if len(customdata) > 2 else point.get("z", "N/A"),
        "dataset_name": customdata[3] if len(customdata) > 3 else "Unknown dataset",
        "pii_type": customdata[4] if len(customdata) > 4 else "N/A",
        "risk_score": customdata[5] if len(customdata) > 5 else point.get("z", "N/A"),
        "sample_data": customdata[6] if len(customdata) > 6 else "N/A",
        "metadata": metadata,
    }


def _selected_cell(click_data: dict[str, Any] | None) -> tuple[str, str] | None:
    if not click_data:
        return None
    point = (click_data.get("points") or [{}])[0]
    payload = _cell_payload(point)
    return str(payload["row_label"]), str(payload["column_label"])


def _info_metric(label: str, value: Any) -> Any:
    return html.Div(
        className="info-metric",
        children=[
            html.Span(label),
            html.Strong(_format_value(value)),
        ],
    )


def _format_value(value: Any) -> str:
    if value is None or value == "":
        return "N/A"
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str)
    return str(value)


def _mask_sample(value: Any) -> str:
    text = str(value or "N/A")
    if text == "N/A" or len(text) <= 4:
        return text
    visible = min(4, max(1, len(text) // 5))
    return f"{text[:visible]}{'*' * min(12, len(text) - visible)}"


def _risk_score(risk_label: str, masking: str) -> float:
    if "critical" in risk_label or "high" in risk_label or "unprotected" in masking:
        return 3.0
    if "moderate" in risk_label or "partial" in masking:
        return 2.0
    if "low" in risk_label or "protected" in masking:
        return 1.0
    return 0.5


def _require_dash() -> None:
    if Dash is None:
        raise ImportError("Dash is required for interactive heatmap UI. Install the 'dash' package.")


def _dash_index_template(title: str) -> str:
    return f"""
<!DOCTYPE html>
<html>
    <head>
        {{%metas%}}
        <title>{title}</title>
        {{%favicon%}}
        {{%css%}}
        <style>
            .heatmap-shell {{
                display: grid;
                grid-template-columns: minmax(0, 1fr) 360px;
                gap: 16px;
                max-width: 1440px;
                margin: 0 auto;
            }}
            .heatmap-main,
            .heatmap-info-panel {{
                background: #fbfcfd;
                border: 1px solid #d4dee6;
                border-radius: 8px;
                box-shadow: 0 18px 40px rgba(19, 35, 49, .08);
                min-width: 0;
            }}
            .info-card {{
                padding: 18px;
                color: #162635;
                font-family: Aptos, Segoe UI, sans-serif;
            }}
            .info-eyebrow {{
                color: #ba4538;
                font-size: 12px;
                font-weight: 800;
                letter-spacing: 0;
                margin: 0 0 8px;
                text-transform: uppercase;
            }}
            .info-card h2 {{
                font-size: 20px;
                line-height: 1.2;
                margin: 0 0 16px;
                overflow-wrap: anywhere;
            }}
            .info-card h3 {{
                font-size: 14px;
                margin: 18px 0 10px;
            }}
            .info-grid {{
                display: grid;
                gap: 10px;
            }}
            .info-metric,
            .metadata-row {{
                border-bottom: 1px solid #e7eef4;
                display: grid;
                gap: 4px;
                padding: 0 0 10px;
            }}
            .info-metric span,
            .metadata-row span,
            .muted {{
                color: #5f7383;
                font-size: 12px;
                font-weight: 700;
                text-transform: uppercase;
            }}
            .info-metric strong,
            .metadata-row strong {{
                font-size: 14px;
                overflow-wrap: anywhere;
            }}
            @media (max-width: 900px) {{
                .heatmap-shell {{
                    grid-template-columns: 1fr;
                }}
            }}
        </style>
    </head>
    <body>
        {{%app_entry%}}
        <footer>
            {{%config%}}
            {{%scripts%}}
            {{%renderer%}}
        </footer>
    </body>
</html>
"""
