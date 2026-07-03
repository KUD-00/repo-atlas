import { createRoot } from 'react-dom/client'
import { App } from './App.jsx'
import './styles.css'

// build.js injects the status payload as window.__ATLAS__ before this bundle.
createRoot(document.getElementById('root')).render(<App data={window.__ATLAS__} />)
