import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './app/App';
import { runDesktopWebviewSmokeIfEnabled } from './app/desktopWebviewSmoke';
import './styles/index.css';

void bootstrap();

async function bootstrap() {
  if (await runDesktopWebviewSmokeIfEnabled()) {
    return;
  }
  ReactDOM.createRoot(document.getElementById('root')!).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  );
}
