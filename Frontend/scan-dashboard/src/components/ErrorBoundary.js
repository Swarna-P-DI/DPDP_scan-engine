import React from "react";

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // Keep the error visible in the browser console for local debugging.
    // eslint-disable-next-line no-console
    console.error("Frontend render error", error, info);
  }

  render() {
    if (this.state.error) {
      return (
        <main className="dashboard-shell">
          <section className="error-banner">
            <strong>Frontend render failed.</strong>
            <p style={{ marginTop: 12 }}>
              {this.state.error?.message || "Unknown React rendering error"}
            </p>
          </section>
        </main>
      );
    }

    return this.props.children;
  }
}
