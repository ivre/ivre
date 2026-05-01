import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { Root } from "./routes/root";
import "./index.css";

const rootElement = document.getElementById("root");
if (!rootElement) {
  throw new Error("Missing #root element in index.html");
}

createRoot(rootElement).render(
  <StrictMode>
    <Root />
  </StrictMode>,
);
