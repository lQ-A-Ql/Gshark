export function onRequest(input) {
  const message = String(input.values.message || "");
  return {
    message: "Echo 完成",
    text: message,
    table: {
      columns: [
        { key: "field", label: "Field" },
        { key: "value", label: "Value" }
      ],
      rows: [
        { field: "length", value: String(message.length) },
        { field: "hasCapture", value: String(Boolean(input.capture_path)) }
      ]
    },
    output: {
      length: message.length,
      hasCapture: Boolean(input.capture_path)
    }
  };
}
