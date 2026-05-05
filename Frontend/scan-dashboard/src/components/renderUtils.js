export const parseMaybeJson = (value) => {
  if (!value || typeof value !== "string") return value;

  const trimmed = value.trim();
  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fenced ? fenced[1].trim() : trimmed;

  try {
    return JSON.parse(candidate);
  } catch {
    return value;
  }
};

export const toDisplayText = (value) => {
  if (value === null || value === undefined || value === "") return "No data available";
  if (typeof value === "string") return value;
  return JSON.stringify(value, null, 2);
};

export const asArray = (value) => {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
};
