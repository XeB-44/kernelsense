# KernelSense Development Brief

Act as a senior Python/Linux security engineer and a world-class product designer. Preserve the lightweight built-in HTTP server and custom HTML/CSS/JavaScript dashboard; do not introduce Streamlit or a frontend build chain. Keep the default bind address at localhost.

Design principles: dark multicolor vibrant visual system; accessible contrast; beginner-friendly explanations; clear status hierarchy; responsive layout; useful empty/loading/error states; no fake real alerts.

Security principles: local-first data handling, redact secrets, never run remediation commands automatically, do not persist OpenRouter keys, and only send an alert to OpenRouter after the user explicitly requests analysis. Clearly disclose what fields will be sent. Treat model output as untrusted advice and label uncertainty.

When making changes, inspect existing files and schemas, make the changes directly, run syntax checks/tests, and report verified results and remaining limitations.
