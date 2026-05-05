import ErrorBoundary from "./components/ErrorBoundary";
import Dashboard from "./pages/Dashboard";
import "./App.css";

function App() {
  return (
    <ErrorBoundary>
      <Dashboard />
    </ErrorBoundary>
  );
}

export default App;
