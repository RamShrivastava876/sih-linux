
import React, { useState, useRef } from 'react';
import axios from 'axios';

function App() {
  const [consent, setConsent] = useState(false);
  const [devices, setDevices] = useState([]);
  const [selectedDevice, setSelectedDevice] = useState('');
  const [method, setMethod] = useState('auto');
  const [progress, setProgress] = useState([]);
  const [erasing, setErasing] = useState(false);
  const [certificate, setCertificate] = useState(null);
  const wsRef = useRef(null);

  const fetchDevices = async () => {
    const res = await axios.get('http://localhost:8000/devices');
    setDevices(res.data);
  };

  const startErase = async () => {
    setErasing(true);
    setProgress([`Started erasing ${selectedDevice} with ${method}`]);
    // Start WebSocket for logs
    wsRef.current = new window.WebSocket(`ws://localhost:8000/logs/${encodeURIComponent(selectedDevice)}`);
    wsRef.current.onmessage = (event) => {
      setProgress((p) => [...p, event.data]);
      if (event.data.includes('Certificate generated.')) {
        wsRef.current.close();
        setErasing(false);
        fetchCertificate();
      }
    };
    wsRef.current.onerror = () => {
      setProgress((p) => [...p, 'WebSocket error.']);
    };
    await axios.post('http://localhost:8000/erase', {
      device_id: selectedDevice,
      method,
    });
  };

  const fetchCertificate = async () => {
    // Fetch JSON for display
    const res = await axios.get('http://localhost:8000/certificate', {
      params: { device_id: selectedDevice, format: 'json' },
    });
    setCertificate(res.data);
  };

  const downloadCert = (format) => {
    const url = `http://localhost:8000/certificate?device_id=${encodeURIComponent(selectedDevice)}&format=${format}`;
    window.open(url, '_blank');
  };

  if (!consent) {
    return (
      <div style={{ padding: 40 }}>
        <h2>This process will permanently erase selected drives. Proceed?</h2>
        <button onClick={() => { setConsent(true); fetchDevices(); }}>I Understand, Continue</button>
      </div>
    );
  }

  if (certificate) {
    return (
      <div style={{ padding: 40 }}>
        <h2>Erase Complete</h2>
        <pre>{JSON.stringify(certificate, null, 2)}</pre>
        <button onClick={() => downloadCert('pdf')}>Download PDF Certificate</button>
        <button onClick={() => downloadCert('json')}>Download JSON Certificate</button>
        <br />
        <button onClick={() => window.location.reload()}>Start Over</button>
      </div>
    );
  }

  return (
    <div style={{ padding: 40 }}>
      <h2>Select Device to Erase</h2>
      <select value={selectedDevice} onChange={e => setSelectedDevice(e.target.value)}>
        <option value="">-- Select --</option>
        {devices.map(d => (
          <option key={d.id} value={d.id}>{d.model} ({d.size})</option>
        ))}
      </select>
      <h3>Erase Method</h3>
      <select value={method} onChange={e => setMethod(e.target.value)}>
        <option value="auto">Auto Secure Erase</option>
        <option value="multi-pass">Multi-pass overwrite</option>
        <option value="crypto-erase">Crypto-erase</option>
      </select>
      <br /><br />
      <button disabled={!selectedDevice || erasing} onClick={startErase}>Erase</button>
      <div style={{ marginTop: 30 }}>
        <h4>Progress</h4>
        <pre>{progress.join('\n')}</pre>
      </div>
    </div>
  );
}

export default App;
