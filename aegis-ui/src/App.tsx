import { useState } from "react";
import { Sidebar } from "./components/Sidebar";
import { Dashboard } from "./pages/Dashboard";
import { DeviceMap } from "./pages/DeviceMap";
import { AuditLog } from "./pages/AuditLog";
import { Settings } from "./pages/Settings";
import { Sanitize } from "./pages/Sanitize";

export type Page = "dashboard" | "devices" | "audit" | "settings" | "sanitize";

function App() {
  const [currentPage, setCurrentPage] = useState<Page>("dashboard");

  const renderPage = () => {
    switch (currentPage) {
      case "dashboard":
        return <Dashboard />;
      case "devices":
        return <DeviceMap />;
      case "audit":
        return <AuditLog />;
      case "settings":
        return <Settings />;
      case "sanitize":
        return <Sanitize />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <>
      <Sidebar currentPage={currentPage} onNavigate={setCurrentPage} />
      <main className="main-content">
        {renderPage()}
      </main>
    </>
  );
}

export default App;
