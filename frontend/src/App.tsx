import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import { Spinner } from "./components/ui";
import { useAuth } from "./auth/AuthContext";
import Dashboard from "./pages/Dashboard";
import Login from "./pages/Login";
import NewScan from "./pages/NewScan";
import Policies from "./pages/Policies";
import ScanDetail from "./pages/ScanDetail";
import Scans from "./pages/Scans";

export default function App() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="grid min-h-full place-items-center">
        <Spinner />
      </div>
    );
  }

  if (!user) return <Login />;

  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="/scan" element={<NewScan />} />
        <Route path="/scans" element={<Scans />} />
        <Route path="/scans/:id" element={<ScanDetail />} />
        <Route path="/policies" element={<Policies />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
