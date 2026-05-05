const chartPalette = {
  high: "#ba4538",
  medium: "#d18a1c",
  low: "#2f7d5a",
  accent: "#0f6c7a",
  accentSoft: "#7fb3bd",
  ink: "#162635",
  grid: "#d7e1e8",
  bg: "#ffffff",
};

const createCanvas = (width = 900, height = 520) => {
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d");
  ctx.fillStyle = chartPalette.bg;
  ctx.fillRect(0, 0, width, height);
  return { canvas, ctx, width, height };
};

const drawTitle = (ctx, title, subtitle) => {
  ctx.fillStyle = chartPalette.ink;
  ctx.font = "700 28px Segoe UI";
  ctx.fillText(title, 40, 50);
  ctx.fillStyle = "#5f7383";
  ctx.font = "16px Segoe UI";
  ctx.fillText(subtitle, 40, 78);
};

const drawLegend = (ctx, items, x, y) => {
  items.forEach((item, index) => {
    const offsetY = y + index * 26;
    ctx.fillStyle = item.color;
    ctx.fillRect(x, offsetY - 10, 14, 14);
    ctx.fillStyle = chartPalette.ink;
    ctx.font = "14px Segoe UI";
    ctx.fillText(`${item.label}: ${item.value}`, x + 22, offsetY + 2);
  });
};

const drawBarChart = ({ title, subtitle, labels, values, colors }) => {
  const { canvas, ctx, width, height } = createCanvas();
  drawTitle(ctx, title, subtitle);

  const max = Math.max(...values, 1);
  const chartLeft = 80;
  const chartBottom = height - 80;
  const chartTop = 130;
  const chartWidth = width - 140;
  const chartHeight = chartBottom - chartTop;
  const barWidth = chartWidth / Math.max(values.length * 1.6, 1);

  ctx.strokeStyle = chartPalette.grid;
  ctx.lineWidth = 1;
  for (let line = 0; line <= 4; line += 1) {
    const y = chartTop + (chartHeight / 4) * line;
    ctx.beginPath();
    ctx.moveTo(chartLeft, y);
    ctx.lineTo(chartLeft + chartWidth, y);
    ctx.stroke();
  }

  values.forEach((value, index) => {
    const x = chartLeft + index * (barWidth * 1.6) + 24;
    const barHeight = (value / max) * (chartHeight - 20);
    const y = chartBottom - barHeight;
    ctx.fillStyle = colors[index];
    ctx.fillRect(x, y, barWidth, barHeight);
    ctx.fillStyle = chartPalette.ink;
    ctx.font = "14px Segoe UI";
    ctx.fillText(String(value), x, y - 8);
    ctx.save();
    ctx.translate(x + 8, chartBottom + 18);
    ctx.rotate(-0.25);
    ctx.fillText(labels[index], 0, 0);
    ctx.restore();
  });

  return canvas.toDataURL("image/png");
};

const drawDonutChart = ({ title, subtitle, segments }) => {
  const { canvas, ctx } = createCanvas();
  drawTitle(ctx, title, subtitle);

  const total = segments.reduce((sum, item) => sum + item.value, 0) || 1;
  const centerX = 280;
  const centerY = 290;
  const radius = 120;
  const innerRadius = 68;
  let startAngle = -Math.PI / 2;

  segments.forEach((segment) => {
    const sweep = (segment.value / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.moveTo(centerX, centerY);
    ctx.arc(centerX, centerY, radius, startAngle, startAngle + sweep);
    ctx.closePath();
    ctx.fillStyle = segment.color;
    ctx.fill();
    startAngle += sweep;
  });

  ctx.beginPath();
  ctx.fillStyle = chartPalette.bg;
  ctx.arc(centerX, centerY, innerRadius, 0, Math.PI * 2);
  ctx.fill();

  ctx.fillStyle = chartPalette.ink;
  ctx.font = "700 30px Segoe UI";
  ctx.fillText(String(total), centerX - 18, centerY - 2);
  ctx.font = "15px Segoe UI";
  ctx.fillStyle = "#5f7383";
  ctx.fillText("total signals", centerX - 38, centerY + 24);

  drawLegend(ctx, segments, 520, 210);
  return canvas.toDataURL("image/png");
};

export const generateVisuals = (context) => {
  const riskDistribution = {
    title: "Risk Distribution",
    subtitle: "Critical, improvement, and observational exposure levels",
    data: [
      { label: "High", value: context.model.risks.filter((item) => item.severity === "high").length, color: chartPalette.high },
      { label: "Medium", value: context.model.risks.filter((item) => item.severity === "medium").length, color: chartPalette.medium },
      { label: "Low", value: context.model.risks.filter((item) => item.severity === "low").length, color: chartPalette.low },
    ],
  };

  const dqDimensions = {
    title: "Data Quality Signals",
    subtitle: "Table-level quality issue counts and quality dimensions",
    data: Object.keys(context.dataQualityInsights.dimensions).map((label) => ({
      label: label.replaceAll("_", " "),
      value: context.dataQualityInsights.issues.length || 0,
      color: chartPalette.accent,
    })),
  };

  const piiExposure = {
    title: "PII Exposure",
    subtitle: "Protected vs unprotected sensitive columns",
    data: [
      {
        label: "Unprotected",
        value: context.model.piiFindings.filter((item) => item.maskingStatus === "NOT_MASKED").length,
        color: chartPalette.high,
      },
      {
        label: "Partially protected",
        value: context.model.piiFindings.filter((item) => item.maskingStatus === "PARTIALLY_MASKED").length,
        color: chartPalette.medium,
      },
      {
        label: "Protected",
        value: context.model.piiFindings.filter((item) => item.maskingStatus === "MASKED").length,
        color: chartPalette.low,
      },
    ],
  };

  const tableCoverage = {
    title: "Table Coverage",
    subtitle: "Rows sampled across scanned tables",
    data: context.model.tables.map((item) => ({
      label: item.table,
      value: item.rowCount,
      color: chartPalette.accentSoft,
    })),
  };

  return {
    riskDistribution,
    dqDimensions,
    piiExposure,
    tableCoverage,
  };
};

export const renderVisuals = async (context) => {
  const visuals = generateVisuals(context);
  return {
    data: visuals,
    images: {
      riskDistribution: drawDonutChart({
        title: visuals.riskDistribution.title,
        subtitle: visuals.riskDistribution.subtitle,
        segments: visuals.riskDistribution.data,
      }),
      dataQuality: drawBarChart({
        title: visuals.dqDimensions.title,
        subtitle: visuals.dqDimensions.subtitle,
        labels: visuals.dqDimensions.data.map((item) => item.label),
        values: visuals.dqDimensions.data.map((item) => item.value),
        colors: visuals.dqDimensions.data.map((item) => item.color),
      }),
      piiExposure: drawDonutChart({
        title: visuals.piiExposure.title,
        subtitle: visuals.piiExposure.subtitle,
        segments: visuals.piiExposure.data,
      }),
      tableCoverage: drawBarChart({
        title: visuals.tableCoverage.title,
        subtitle: visuals.tableCoverage.subtitle,
        labels: visuals.tableCoverage.data.map((item) => item.label),
        values: visuals.tableCoverage.data.map((item) => item.value),
        colors: visuals.tableCoverage.data.map((item) => item.color),
      }),
    },
  };
};
