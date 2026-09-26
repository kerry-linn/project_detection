import { Navigate, Route, Routes } from "react-router";

import { useAuth } from "./auth/AuthContext";
import { Layout } from "./components/Layout";
import { homePath } from "./format";
import { AlertDetailPage } from "./pages/AlertDetail";
import { AlertsPage } from "./pages/Alerts";
import { DocumentDetailPage } from "./pages/DocumentDetail";
import { DocumentsPage } from "./pages/Documents";
import { LoginPage } from "./pages/Login";

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<Layout />}>
        <Route index element={<Home />} />
        <Route path="documents" element={<DocumentsPage />} />
        <Route path="documents/:documentId" element={<DocumentDetailPage />} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="alerts/:alertKey" element={<AlertDetailPage />} />
        <Route path="*" element={<p>Page not found.</p>} />
      </Route>
    </Routes>
  );
}

function Home() {
  const { user } = useAuth();
  return user === null ? null : <Navigate to={homePath(user.role)} replace />;
}
