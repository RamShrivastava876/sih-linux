import React, { useState, useRef, useEffect } from 'react';
import axios from 'axios';
import { FiRefreshCcw, FiHardDrive, FiShield, FiPlay, FiMoon, FiSun, FiGlobe, FiLock, FiZap, FiCpu, FiFileText } from 'react-icons/fi';
import LogoAsset from './logo.svg';
import { motion, AnimatePresence } from 'framer-motion';

// Rewritten clean implementation (old duplicated code removed)

// Inline component now replaced by imported SVG asset
const LogoMark = () => <img src={LogoAsset} alt="CertiWipe" className="w-[34px] h-[34px] select-none" draggable={false} />;

const fadeVariant = {
  hidden: { opacity:0, y:8 },
  visible: { opacity:1, y:0, transition:{ duration:.45, ease:[.25,.1,.25,1] } }
};

const SectionCard = ({ title, children, className = '', icon:Icon }) => (
  <motion.div variants={fadeVariant} initial="hidden" animate="visible" className={`eco-card hover-rise ${className}`} style={{minHeight: '220px'}}>
    {title && (
      <h3 className="text-lg font-semibold mb-3 tracking-wide text-emerald-300 flex items-center gap-2">
        {Icon && <Icon className="text-emerald-400" size={18} />}{title}
      </h3>
    )}
    {children}
  </motion.div>
);

const toneMap = {
  emerald: 'bg-emerald-900/40 border-emerald-600/40 text-emerald-300',
  cyan: 'bg-cyan-900/40 border-cyan-600/40 text-cyan-300',
  amber: 'bg-amber-900/40 border-amber-600/40 text-amber-300'
};
const Pill = ({ children, tone='emerald' }) => (
  <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${toneMap[tone] || toneMap.emerald}`}>{children}</span>
);

// Simple i18n dictionary scaffold (en + hi)
const messages = {
  en: {
    safetyNotice: 'Safety Notice',
    proceed: 'I Understand – Continue',
    selectDevice: '1. Select Device',
    wipeMethod: '2. Wipe Method',
    preconditions: '3. Preconditions',
    startErase: 'Start Erase',
    erasing: 'Erasing...',
    noSpecial: 'No special preconditions.',
  noticeBody: 'This process will irreversibly remove data from selected storage devices. Ensure you have backups before you proceed.',
  dashboardTag: 'Certified Eco & Trust Erasure',
  eraseComplete: 'Erase Complete',
  certificate: 'Certificate',
  downloadPdf: 'Download PDF',
  downloadJson: 'Download JSON',
  downloadZip: 'Download Bundle (ZIP)',
  energy: 'Energy',
  carbon: 'CO₂',
  entropy: 'Entropy',
  confidence: 'Confidence',
  ecoImpact: 'Eco Impact',
  energyReduced: 'Energy Used',
  co2Reduced: 'CO₂ Estimated',
  verificationSummary: 'Verification Summary',
  verifyErasure: 'Verify Erasure',
  startOver: 'Start Over',
  refresh: 'Refresh',
  loading: 'Loading...',
  selected: 'Selected',
  devicesLabel: 'Devices',
  methodLabel: 'Method',
  androidChecklist: 'Android Checklist',
  windowsBitlocker: 'Windows / BitLocker',
  status: 'Status',
  encryptionStatus: 'Encryption status',
  unlock: 'Unlock',
  cancel: 'Cancel',
  value: 'Value',
  keyFilePath: 'Key File Path',
  trust: 'Trust',
  realTimeProgress: 'Real-Time Progress',
  noActivity: 'No activity yet.',
  certificatesTab: 'CERTIFICATES',
  devicesTab: 'DEVICES',
  progressTab: 'PROGRESS',
  noCertificates: 'No certificates yet.',
  doNotDisconnect: 'Do not disconnect device...' 
  , adminPrivilegesNeeded: 'Run backend as Administrator to view full BitLocker encryption status.'
  },
  hi: {
    safetyNotice: 'सुरक्षा सूचना',
    proceed: 'मैं समझता हूँ – आगे बढ़ें',
    selectDevice: '१. डिवाइस चुनें',
    wipeMethod: '२. वाइप विधि',
    preconditions: '३. पूर्व शर्तें',
    startErase: 'मिटाना शुरू करें',
    erasing: 'मिटाया जा रहा है...',
    noSpecial: 'कोई विशेष पूर्व शर्त नहीं।',
  noticeBody: 'यह प्रक्रिया चयनित स्टोरेज डिवाइसों से डेटा को स्थायी रूप से हटा देगी। आगे बढ़ने से पहले अपने बैकअप सुनिश्चित करें।',
  dashboardTag: 'प्रमाणित ईको एवं ट्रस्ट इरेज़र',
  eraseComplete: 'मिटाना पूर्ण',
  certificate: 'प्रमाणपत्र',
  downloadPdf: 'PDF डाउनलोड',
  downloadJson: 'JSON डाउनलोड',
  downloadZip: 'ZIP बंडल डाउनलोड',
  energy: 'ऊर्जा',
  carbon: 'CO₂',
  entropy: 'एंट्रॉपी',
  confidence: 'विश्वास स्तर',
  ecoImpact: 'ईको प्रभाव',
  energyReduced: 'ऊर्जा उपयोग',
  co2Reduced: 'अनुमानित CO₂',
  verificationSummary: 'सत्यापन सारांश',
  verifyErasure: 'मिटाने की पुष्टि',
  startOver: 'फिर से शुरू करें',
  refresh: 'रिफ्रेश',
  loading: 'लोड हो रहा है...',
  selected: 'चयनित',
  devicesLabel: 'डिवाइस',
  methodLabel: 'विधि',
  androidChecklist: 'एंड्रॉइड चेकलिस्ट',
  windowsBitlocker: 'विंडोज / बिटलॉकर',
  status: 'स्थिति',
  encryptionStatus: 'एन्क्रिप्शन स्थिति',
  unlock: 'अनलॉक',
  cancel: 'रद्द',
  value: 'मान',
  keyFilePath: 'की फ़ाइल पथ',
  trust: 'विश्वास',
  realTimeProgress: 'रीयल-टाइम प्रगति',
  noActivity: 'अभी तक कोई गतिविधि नहीं।',
  certificatesTab: 'प्रमाणपत्र',
  devicesTab: 'डिवाइस',
  progressTab: 'प्रगति',
  noCertificates: 'कोई प्रमाणपत्र नहीं।',
  doNotDisconnect: 'डिवाइस को न हटाएँ...' 
  , adminPrivilegesNeeded: 'पूर्ण बिटलॉकर एन्क्रिप्शन स्थिति देखने के लिए बैकएंड को प्रशासक अधिकारों (Administrator) के साथ चलाएँ।'
  }
};

function App() {
  const [unlockModal, setUnlockModal] = useState({ open: false, drive: '', method: 'password', value: '' });
  const [consent, setConsent] = useState(false);
  const [theme, setTheme] = useState('dark');
  const [lang, setLang] = useState('en');
  const [devices, setDevices] = useState([]);
  const [apiKey, setApiKey] = useState('');
  const [devicesLoading, setDevicesLoading] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState('');
  const [method, setMethod] = useState('');
  const [subMethod, setSubMethod] = useState('');
  const [progress, setProgress] = useState([]);
  const [erasing, setErasing] = useState(false);
  const [certificate, setCertificate] = useState(null);
  const [checklist, setChecklist] = useState({ adb: false, connected: false, encrypted: false });
  const [androidEncryption, setAndroidEncryption] = useState(null);
  const [winBitLocker, setWinBitLocker] = useState({ status: null, unlocking: false, details: [] });
  const [bitlockerRaw, setBitlockerRaw] = useState(null);
  const [wipeMethods, setWipeMethods] = useState([]);
  const [activeTab, setActiveTab] = useState('devices');
  const [verification, setVerification] = useState(null);
  const [certLogs, setCertLogs] = useState({ lines: [], total: 0, warnCount: 0, hasMore: false });
  const [allowlist, setAllowlist] = useState([]);
  const [smartData, setSmartData] = useState(null);
  const [detailedMode, setDetailedMode] = useState(true);
  const wsRef = useRef(null);
  const progressPollRef = useRef(null);
  const [detailedProgress, setDetailedProgress] = useState(null);
  const progressHistoryRef = useRef([]); // for speed & ETA smoothing
  const logTailPollRef = useRef(null);
  const lastLogIndexRef = useRef(0);
  const [sizeOverrides, setSizeOverrides] = useState({});
  const [platformCaps, setPlatformCaps] = useState(null);
  const [showOnlyWarnings, setShowOnlyWarnings] = useState(false);

  const isAndroid = devices.find(d => d.id === selectedDevice && d.type && d.type.startsWith('Android'));
  // Adjusted: backend now returns type 'Windows' for Windows disks
  const isWindowsDrive = devices.find(d => d.id === selectedDevice && (d.type === 'Windows' || d.type === 'SSD' || d.type === 'HDD'));
  // Mock file device (safe test sandbox)
  const isMock = !!devices.find(d => d.id === selectedDevice && d.id.startsWith('mockfile:'));

  // Helper: parse various size representations to bytes
  const parseToBytes = (val) => {
    if (typeof val === 'number') return isFinite(val) ? val : null;
    if (typeof val === 'string') {
      const s = val.trim();
      const m = s.match(/^([0-9]+(?:\.[0-9]+)?)\s*(b|bytes|kb|kib|mb|mib|gb|gib)?$/i);
      if (m) {
        const num = parseFloat(m[1]);
        const unit = (m[2] || 'bytes').toLowerCase();
        const pow2 = { b:1, bytes:1, kib:1024, mib:1024**2, gib:1024**3 };
        const dec = { kb:1e3, mb:1e6, gb:1e9 };
        if (unit in pow2) return Math.round(num * pow2[unit]);
        if (unit in dec) return Math.round(num * dec[unit]);
        if (/^\d+$/.test(s)) return parseInt(s,10);
      } else if (/^\d+$/.test(s)) {
        return parseInt(s,10);
      }
    }
    return null;
  };

  const fetchDevices = async (detailedParam) => {
    const detailed = (typeof detailedParam === 'boolean') ? detailedParam : detailedMode;
    setDevicesLoading(true);
    try {
      const res = await axios.get('http://localhost:8000/devices', { params:{ detailed, api_key: apiKey || undefined }});
      const list = Array.isArray(res.data) ? res.data : [];
      setDevices(list);
      // Attempt accurate size overrides for devices with missing/too-small size
      setSizeOverrides({});
      const MIN_BYTES = 1024 * 1024; // 1 MiB
      list.forEach(async (d) => {
        try {
          let reported = (typeof d.size_bytes === 'number' && isFinite(d.size_bytes)) ? d.size_bytes : parseToBytes(d.size);
          if (!reported || reported < MIN_BYTES) {
            const r = await axios.get('http://localhost:8000/device_size', { params: { device_id: d.id, api_key: apiKey || undefined }});
            const sz = r?.data?.size_bytes;
            if (typeof sz === 'number' && isFinite(sz) && sz > 0) {
              setSizeOverrides(prev => ({ ...prev, [d.id]: sz }));
            }
          }
        } catch (_) { /* ignore per-device errors */ }
      });
    } catch(e){ /* ignore */ } finally { setDevicesLoading(false); }
  };
  const fetchAllowlist = async () => { try { const r = await axios.get('http://localhost:8000/allowlist', { params:{ api_key: apiKey || undefined }}); setAllowlist(r.data);} catch { /* ignore */ } };

  const startErase = async () => {
    setErasing(true);
    setProgress([`▶ Starting erase ${selectedDevice} with method ${method}`]);
    wsRef.current = new window.WebSocket(`ws://localhost:8000/logs/${encodeURIComponent(selectedDevice)}`);
    wsRef.current.onmessage = (event) => {
      setProgress(p => [...p, event.data]);
      if (/Certificate generated/i.test(event.data)) { wsRef.current.close(); setErasing(false); fetchCertificate(); }
    };
    wsRef.current.onerror = () => {
      setProgress(p => [...p, '⚠ WebSocket error – switching to fallback log polling']);
      try { wsRef.current && wsRef.current.close(); } catch(_){}
      // Start fallback polling
      if (logTailPollRef.current) clearInterval(logTailPollRef.current);
      lastLogIndexRef.current = 0;
      const poll = async () => {
        try {
          const r = await axios.get('http://localhost:8000/logs_tail', { params:{ device_id: selectedDevice, since: lastLogIndexRef.current, api_key: apiKey || undefined }});
          if (Array.isArray(r.data?.lines) && r.data.lines.length){
            lastLogIndexRef.current = r.data.end;
            setProgress(prev => [...prev, ...r.data.lines]);
            if (r.data.lines.some(l=>/Certificate generated/i.test(l))) {
              setErasing(false);
              fetchCertificate();
              clearInterval(logTailPollRef.current);
            }
          }
        } catch(_){}
      };
      poll();
      logTailPollRef.current = setInterval(poll, 1000);
    };
    try {
  await axios.post('http://localhost:8000/erase?confirm=true', { device_id: selectedDevice, method, sub_method: subMethod || undefined });
    } catch (e) {
      if (e.response && e.response.status === 412) {
        // auto-add then retry
        try {
          await axios.post('http://localhost:8000/allow_device', null, { params:{ device_id: selectedDevice }});
          setAllowlist(a=>[...new Set([...a, selectedDevice])]);
          await axios.post('http://localhost:8000/erase?confirm=true', { device_id: selectedDevice, method, sub_method: subMethod || undefined });
          setProgress(p=>[...p,'Added to allowlist and restarted erase.']);
        } catch {
          setProgress(p=>[...p,'Failed to auto-add device to allowlist.']);
        }
      } else {
        setProgress(p=>[...p, `Erase start error: ${e.message}`]);
      }
    }
    // Start polling detailed progress
    if (progressPollRef.current) clearInterval(progressPollRef.current);
    progressPollRef.current = setInterval(async () => {
      try {
        const r = await axios.get('http://localhost:8000/progress_detailed', { params:{ device_id: selectedDevice }});
        const now = Date.now();
        if (r.data && typeof r.data.bytes_written === 'number') {
          progressHistoryRef.current.push({ t: now, b: r.data.bytes_written });
          if (progressHistoryRef.current.length > 10) progressHistoryRef.current.shift();
          const first = progressHistoryRef.current[0];
          const last = progressHistoryRef.current[progressHistoryRef.current.length -1];
          let speedBps = 0;
          if (last && first && last.t !== first.t) {
            speedBps = (last.b - first.b) / ((last.t - first.t)/1000);
          }
          const speedMBs = speedBps/1_000_000;
          let etaSec = null;
          if (speedBps > 0 && r.data.total_bytes) {
            const remaining = Math.max(0, r.data.total_bytes - r.data.bytes_written);
            etaSec = remaining / speedBps;
          }
          setDetailedProgress({ ...r.data, _speedMBs: speedMBs, _etaSec: etaSec });
        } else {
          setDetailedProgress(r.data);
        }
      } catch (_) { /* ignore */ }
    }, 1200);
    setActiveTab('progress');
  };

  const fetchCertificate = async () => {
    const res = await axios.get('http://localhost:8000/certificate', { params: { device_id: selectedDevice, format: 'json' } });
            setCertificate(res.data);
          };
  const downloadCert = (format) => window.open(`http://localhost:8000/certificate?device_id=${encodeURIComponent(selectedDevice)}&format=${format}`, '_blank');
  const downloadZip = () => window.open(`http://localhost:8000/certificate_export?device_id=${encodeURIComponent(selectedDevice)}`, '_blank');
  const fetchCertLogs = async () => {
    if (!selectedDevice) return;
    try {
      // First probe to know total
      const r0 = await axios.get('http://localhost:8000/logs_tail', { params:{ device_id: selectedDevice, since: 0, limit: 1, api_key: apiKey || undefined }});
      const total = typeof r0.data?.total === 'number' ? r0.data.total : 0;
      const tail = Math.max(0, total - 200);
      const r = await axios.get('http://localhost:8000/logs_tail', { params:{ device_id: selectedDevice, since: tail, limit: 250, api_key: apiKey || undefined }});
      const lines = Array.isArray(r.data?.lines) ? r.data.lines : [];
      const warnCount = lines.filter(l => /(fail|error)/i.test(l)).length;
      setCertLogs({ lines, total: r.data?.total || total || lines.length, warnCount, hasMore: !!r.data?.has_more });
    } catch(_) {
      setCertLogs({ lines: [], total: 0, warnCount: 0, hasMore: false });
    }
  };
  const verifyErasure = async () => {
    setVerification('Verifying...');
    try {
      const r = await axios.get('http://localhost:8000/verify_erasure', { params:{ device_id: selectedDevice }});
      setVerification(r.data);
    } catch {
      setVerification('Verification failed');
    } finally {
      // Also refresh logs near verification
      fetchCertLogs();
    }
  };

  // When certificate view is shown, auto-load recent logs
  useEffect(() => {
    if (certificate && selectedDevice) {
      fetchCertLogs();
    }
  }, [certificate, selectedDevice, apiKey]);

  // Effects
  useEffect(() => { axios.get('http://localhost:8000/methods').then(r => setWipeMethods(r.data)).catch(()=>{}); }, []);
  useEffect(() => { if (consent) { fetchDevices(); fetchAllowlist(); } }, [consent, apiKey, detailedMode]);
  // Reset android-specific selections when leaving Android context
  useEffect(()=>{
    if(!method) return;
    if(!isAndroid && method.startsWith('android_')) { setMethod(''); setSubMethod(''); return; }
    if(!isMock && method.startsWith('mock_')) { setMethod(''); setSubMethod(''); return; }
  }, [isAndroid, isMock, method]);
  useEffect(() => { if (isAndroid) { const serial = selectedDevice.split(':')[1]; fetch(`http://localhost:8000/android_encryption?serial=${serial}`).then(r=>r.json()).then(d=> setAndroidEncryption(d.encrypted?'Encrypted':'Not Encrypted')).catch(()=>setAndroidEncryption(null)); } else setAndroidEncryption(null); }, [selectedDevice, isAndroid]);
  // Fetch platform capabilities for selected device
  useEffect(() => {
    if (!selectedDevice) { setPlatformCaps(null); return; }
    const params = new URLSearchParams({ device_id: selectedDevice });
    if (apiKey) params.set('api_key', apiKey);
    axios.get(`http://localhost:8000/platform_capabilities?${params.toString()}`)
      .then(r=> setPlatformCaps(r.data))
      .catch(()=> setPlatformCaps(null));
  }, [selectedDevice, apiKey]);
  useEffect(() => {
    if (!isWindowsDrive) { setWinBitLocker({ status:null, unlocking:false, details:[] }); setBitlockerRaw(null); return; }
    const url = `http://localhost:8000/bitlocker_status?device_id=${encodeURIComponent(selectedDevice)}`;
    fetch(url)
      .then(r=>r.json())
      .then(d=>{
        setBitlockerRaw(d);
        if (Array.isArray(d.results) && d.results.length) {
          const listStr = d.results.map(x=>`${x.drive}: ${x.status}`).join(', ');
          setWinBitLocker({ status: d.status || listStr || 'Unknown', unlocking:false, details:d.results });
        } else {
          let msg = 'Unknown';
          if (d.status === 'admin_required') msg = 'Admin required';
          else if (d.status === 'no_mapping') msg = 'No mapping';
          else if (d.status) msg = d.status;
          else if (d.message) msg = d.message;
          setWinBitLocker({ status: msg, unlocking:false, details: [] });
        }
      })
      .catch(err=> { console.warn('BitLocker status fetch failed', err); setWinBitLocker({ status:'Error', unlocking:false, details:[] }); setBitlockerRaw({ error: String(err) }); });
  }, [selectedDevice, isWindowsDrive]);
  // SMART fetch (Linux only currently)
  useEffect(()=>{
    setSmartData(null);
    const dev = devices.find(d=>d.id===selectedDevice);
    if(!dev) return;
    if(dev.type === 'Linux'){
      fetch(`http://localhost:8000/smart?device_id=${encodeURIComponent(selectedDevice)}`)
        .then(r=>r.json()).then(d=>setSmartData(d)).catch(()=>setSmartData(null));
    }
  }, [selectedDevice, devices]);

  const t = key => (messages[lang] && messages[lang][key]) || key;

  // Theme effect
  useEffect(()=>{
    const root = document.documentElement;
    if(theme==='light') {
      root.classList.remove('dark');
    } else {
      root.classList.add('dark');
    }
    root.classList.remove('light');
    if(theme==='light') root.classList.add('light');
  },[theme]);
  useEffect(()=>{ document.documentElement.lang = lang === 'hi' ? 'hi' : 'en'; },[lang]);
  // Cleanup progress polling on unmount
  useEffect(()=>()=>{ if(progressPollRef.current) clearInterval(progressPollRef.current); },[]);
  useEffect(()=>()=>{ if(logTailPollRef.current) clearInterval(logTailPollRef.current); },[]);

  if (!consent) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-eco-gradient px-6">
        <div className="max-w-xl w-full bg-slate-900/80 backdrop-blur rounded-2xl border border-emerald-600/40 p-10 shadow-2xl">
          <h1 className="text-3xl font-bold eco-gradient-text mb-4">CertiWipe {t('safetyNotice')}</h1>
          <p className="text-slate-300 text-sm leading-relaxed mb-6">{t('noticeBody')}</p>
          <div className="flex gap-3 mb-4">
            <select value={lang} onChange={e=>setLang(e.target.value)} className="bg-slate-800 border border-slate-600 rounded px-3 py-2 text-sm">
              <option value="en">English</option>
              <option value="hi">हिन्दी</option>
            </select>
            <button onClick={()=>setTheme(th=>th==='dark'?'light':'dark')} className="btn-secondary" type="button">{theme==='dark'?'Light':'Dark'}</button>
          </div>
          <button onClick={()=>setConsent(true)} className="btn-primary">{t('proceed')}</button>
        </div>
      </div>
    );
  }

          // Certificate view
          if (certificate) {
            return (
              <div className="min-h-screen bg-slate-950 text-slate-100 p-8 space-y-6">
                <h2 className="text-2xl font-semibold flex items-center gap-3"><span className="eco-gradient-text">{t('eraseComplete')}</span> <Pill>{t('certificate')}</Pill></h2>
                <SectionCard>
                  <pre className="text-xs max-h-[50vh] overflow-auto leading-relaxed">
                    {JSON.stringify(certificate,null,2)}
                  </pre>
                  <div className="flex flex-wrap gap-3 mt-4 items-center">
                    <button onClick={()=>downloadCert('pdf')} className="btn-primary">{t('downloadPdf')}</button>
                    <button onClick={()=>downloadCert('json')} className="btn-secondary">{t('downloadJson')}</button>
                    <button onClick={downloadZip} className="btn-secondary">{t('downloadZip')}</button>
                    <button onClick={verifyErasure} className="btn-secondary">{t('verifyErasure')}</button>
                    <button onClick={()=>window.open(`http://localhost:8000/logs_export?device_id=${encodeURIComponent(selectedDevice)}`, '_blank')} className="btn-secondary">Download Full Logs</button>
                    <button onClick={()=>window.location.reload()} className="btn-danger ml-auto">{t('startOver')}</button>
                  </div>
                  {/* Logs & Warnings compact panel */}
                  <div className="mt-4 grid md:grid-cols-2 gap-4">
                    <div className="border border-slate-700 rounded-lg p-3 bg-slate-900/60">
                      <div className="flex items-center justify-between mb-2">
                        <h4 className="font-semibold text-emerald-300 text-sm">Logs & Warnings</h4>
                        <div className="flex items-center gap-2 text-[10px]">
                          <span className={`px-2 py-0.5 rounded ${certLogs.warnCount? 'bg-amber-900/40 text-amber-300 border border-amber-600/40':'bg-emerald-900/40 text-emerald-300 border border-emerald-600/40'}`}>Warnings: {certLogs.warnCount}</span>
                          <button onClick={fetchCertLogs} className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 border border-slate-600">Refresh</button>
                        </div>
                      </div>
                      <pre className="text-[10px] max-h-48 overflow-auto whitespace-pre-wrap leading-snug">{(certLogs.lines && certLogs.lines.length)? certLogs.lines.join('\n') : 'No logs yet.'}</pre>
                      {certLogs.hasMore && <div className="text-[10px] text-slate-400 mt-1">Showing recent tail. View full logs via API.</div>}
                    </div>
                    {/* Placeholder for any future quick metrics or controls */}
                    <div className="hidden md:block"></div>
                  </div>
                  {certificate?.qr_png_b64 && (
                    <div className="mt-6 flex flex-col items-start gap-2">
                      <span className="text-[11px] uppercase tracking-wide text-slate-400">Verification QR</span>
                      <img
                        src={`data:image/png;base64,${certificate.qr_png_b64}`}
                        alt="Certificate QR"
                        className="border border-slate-700 rounded bg-white p-2 shadow"
                      />
                    </div>
                  )}
                  {verification && (
                    <div className="mt-6 border border-slate-700 rounded-lg p-4 bg-slate-900/60">
                      <h4 className="font-semibold mb-2 text-emerald-300">Verification Report</h4>
                      {typeof verification === 'string' ? (
                        <pre className="text-xs whitespace-pre-wrap">{verification}</pre>
                      ) : (
                        <div className="space-y-2 text-[11px]">
                          <div className="flex flex-wrap gap-4">
                            {'entropy_score' in verification && <span>{t('entropy')}: <strong className="text-emerald-300">{verification.entropy_score}</strong></span>}
                            {'entropy_min' in verification && verification.entropy_min !== null && <span>Min: <strong>{verification.entropy_min}</strong></span>}
                            {'entropy_max' in verification && verification.entropy_max !== null && <span>Max: <strong>{verification.entropy_max}</strong></span>}
                            {'entropy_stddev' in verification && verification.entropy_stddev !== null && <span>σ: <strong>{verification.entropy_stddev}</strong></span>}
                            {'confidence' in verification && <span>{t('confidence')}: <strong className="text-cyan-300">{verification.confidence}</strong></span>}
                            <span>Warnings: <strong className={verification.warnings? 'text-amber-400':'text-emerald-400'}>{verification.warnings}</strong></span>
                          </div>
                          {verification.entropy_samples && verification.entropy_samples.length>0 && (
                            <details className="text-slate-400">
                              <summary className="cursor-pointer">Entropy Samples ({verification.entropy_samples.length})</summary>
                              <div className="mt-2 max-h-40 overflow-auto space-y-1">
                                {verification.entropy_samples.slice(0,25).map((s,i)=>(
                                  <div key={i} className="flex justify-between"><span>0x{s.offset.toString(16)}</span><span>{s.entropy_norm}</span></div>
                                ))}
                              </div>
                            </details>
                          )}
                          <details className="text-slate-400">
                            <summary className="cursor-pointer">Raw JSON</summary>
                            <pre className="text-[10px] whitespace-pre-wrap mt-2 max-h-52 overflow-auto">{JSON.stringify(verification,null,2)}</pre>
                          </details>
                          {certificate?.trust_components && (
                            <details className="text-slate-400">
                              <summary className="cursor-pointer">Trust Components</summary>
                              <div className="mt-2 grid grid-cols-2 gap-1 text-[10px]">
                                {Object.entries(certificate.trust_components).map(([k,v])=> <div key={k} className="flex justify-between"><span>{k}</span><span className="text-emerald-300">{v}</span></div>)}
                              </div>
                            </details>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </SectionCard>
              </div>
            );
          }

          const methodMeta = wipeMethods.find(w=>w.id===method);
          const disableErase = !selectedDevice || !method || erasing || (isAndroid && !(checklist.adb && checklist.connected && checklist.encrypted));

          // Trust gauge (simple circle) component inline
          const TrustGauge = ({ value=0 }) => {
            const pct = Math.max(0, Math.min(100, value));
            const stroke = 8;
            const r = 54 - stroke;
            const circ = 2 * Math.PI * r;
            const offset = circ - (pct/100)*circ;
            return (
              <div className="trust-gauge">
                <svg viewBox="0 0 108 108">
                  <circle cx="54" cy="54" r={r} stroke="#1e293b" strokeWidth={stroke} fill="none" />
                  <circle cx="54" cy="54" r={r} stroke="url(#grad)" strokeLinecap="round" strokeWidth={stroke} fill="none" strokeDasharray={circ} strokeDashoffset={offset} />
                  <defs>
                    <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="0%">
                      <stop offset="0%" stopColor="#10b981" />
                      <stop offset="50%" stopColor="#06b6d4" />
                      <stop offset="100%" stopColor="#0891b2" />
                    </linearGradient>
                  </defs>
                </svg>
                <div className="trust-gauge-value">{pct}</div>
              </div>
            );
          };

          const trustScoreVal = certificate?.trust_score || verification?.trust_score || 0;

          return (
            <div className={`min-h-screen ${theme==='dark' ? 'dark':'light'}`} style={{background: 'linear-gradient(135deg,var(--bg-gradient-from),var(--bg-gradient-mid),var(--bg-gradient-to))', color: 'var(--text-primary)'}}>
                      <header className="glass-header px-6 md:px-8 pt-5 pb-4 mb-6 gap-4 lg:flex-row lg:items-center lg:gap-10">
                        {/* Top erase progress bar */}
                        {(erasing || (detailedProgress && (detailedProgress.status==='running' || detailedProgress.status==='verifying'))) && (
                          (()=>{
                            let percent = null;
                            if (detailedProgress && detailedProgress.total_bytes && detailedProgress.passes_total) {
                              const denom = (detailedProgress.total_bytes * detailedProgress.passes_total) || 1;
                              percent = Math.min(100, (detailedProgress.bytes_written/denom)*100);
                              if (detailedProgress.completed_at) percent = 100;
                            }
                            return (
                              <div className="erase-progress-bar">
                                <div className={`erase-progress-indicator ${percent===null? 'indeterminate':''}`} style={percent!==null? {width: percent+'%'}: undefined} />
                              </div>
                            );
                          })()
                        )}
                <div className="flex items-center gap-3 min-w-[220px]">
                  <LogoMark />
                  <div className="flex flex-col">
                    <h1 className="text-2xl font-bold eco-gradient-text tracking-wide leading-tight flex items-center gap-2">
                      CertiWipe <span className="hidden sm:inline">Dashboard</span>
                    </h1>
                    <span className="mt-0.5 text-[10px] uppercase tracking-wider text-slate-400 font-medium">{t('dashboardTag')}</span>
                  </div>
                </div>
                {/* Navigation: keep single row on large screens; allow wrap only below md */}
                        <nav className="flex gap-2 flex-wrap sm:flex-nowrap lg:flex-nowrap order-3 lg:order-none relative" style={{maxWidth:'100%', rowGap:'0.4rem'}}>
                          {['devices','progress','certificates'].map(tab => (
                            <button
                              key={tab}
                              onClick={()=>setActiveTab(tab)}
                              className={`relative px-4 py-2 rounded-lg text-sm font-medium transition shrink-0 border flex items-center gap-1 focus:outline-none nav-btn ${activeTab===tab? 'bg-slate-900/50 dark:bg-slate-800/50 text-white border-emerald-500/50 shadow inner-glow':'bg-slate-800/40 border-slate-700 hover:bg-slate-700/50'} `}
                            >
                              {tab==='devices' && <FiHardDrive />}
                              {tab==='progress' && <FiZap />}
                              {tab==='certificates' && <FiFileText />}
                              {tab==='devices'?t('devicesTab'):tab==='progress'?t('progressTab'):t('certificatesTab')}
                              {activeTab===tab && (
                                <motion.span layoutId="nav-underline" className="nav-underline" transition={{ type:'spring', stiffness:420, damping:30 }} />
                              )}
                            </button>
                          ))}
                        </nav>
                <div className="lg:ml-auto flex flex-wrap gap-3 md:gap-4 text-[11px] md:text-[11px] text-slate-400 pt-1 md:pt-0 border-t md:border-t-0 border-slate-800 md:pl-0 pl-1 items-center">
                  <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"/>{t('devicesLabel')}: {devices.length}</span>
                  <input value={apiKey} onChange={e=>setApiKey(e.target.value.trim())} placeholder="API Key" className="px-2 py-1 rounded border border-slate-600 bg-slate-800/60 text-xs w-32 focus:outline-none focus:ring-2 focus:ring-emerald-500/50" />
                  <span>{t('methodLabel')}: <span className="text-emerald-300 font-mono">{method || '-'}</span></span>
                  <button
                    onClick={()=>setTheme(th=>th==='dark'?'light':'dark')}
                    className={`px-3 py-1 rounded text-xs border transition flex items-center gap-1 font-medium ${theme==='dark'
                      ? 'bg-slate-800/70 hover:bg-slate-700/70 border-slate-600 text-slate-200'
                      : 'bg-white/80 hover:bg-white border-slate-300 text-slate-700 shadow-sm'}`}
                  >{theme==='dark'? <><FiSun/> Light</>: <><FiMoon/> Dark</>}</button>
                  <select
                    value={lang}
                    onChange={e=>setLang(e.target.value)}
                    className={`rounded px-2 py-1 text-xs border transition flex items-center gap-1 pl-7 relative ${theme==='dark'
                      ? 'bg-slate-800/60 border-slate-600 text-slate-200'
                      : 'bg-white/70 hover:bg-white border-slate-300 text-slate-700 shadow-sm'}`}
                  >
                    <option value="en">EN</option>
                    <option value="hi">HI</option>
                  </select>
                  {trustScoreVal ? <div className="flex items-center gap-2"><TrustGauge value={trustScoreVal} /><span className="text-[10px] uppercase tracking-wide">Trust</span></div>: null}
                </div>
              </header>
              <main className="px-8 pb-16 space-y-8 pt-2">
                {activeTab==='devices' && (
                  <div className="grid lg:grid-cols-3 gap-8 items-start content-start">
                    <SectionCard title={t('selectDevice')} icon={FiHardDrive} className="lg:col-span-1">
                      {/* Allowlist badge */}
                      {selectedDevice && <div className="mb-2 text-[10px] flex items-center gap-2">
                        {allowlist.includes(selectedDevice) ? <span className="px-2 py-0.5 rounded bg-emerald-700/60 text-emerald-200">Allowlisted</span> : <span className="px-2 py-0.5 rounded bg-amber-700/60 text-amber-200">Not Allowlisted</span>}
                        {selectedDevice && !allowlist.includes(selectedDevice) && <button onClick={async()=>{ try { await axios.post('http://localhost:8000/allow_device', null, { params:{ device_id: selectedDevice }}); setAllowlist(a=>[...a, selectedDevice]); } catch{} }} className="text-[10px] underline text-emerald-300">Add</button>}
                        {selectedDevice && allowlist.includes(selectedDevice) && <button onClick={async()=>{ try { await axios.delete('http://localhost:8000/allow_device', { params:{ device_id: selectedDevice }}); setAllowlist(a=>a.filter(d=>d!==selectedDevice)); } catch{} }} className="text-[10px] underline text-amber-300">Remove</button>}
                      </div>}
                      <div className="flex items-center gap-3 mb-3 flex-wrap">
                        <button onClick={()=>fetchDevices()} className={`px-3 py-1.5 text-xs rounded border transition font-medium flex items-center gap-1 ${theme==='dark'? 'bg-slate-800 hover:bg-slate-700 border-slate-600 text-slate-200':'bg-white hover:bg-emerald-50 border-slate-300 text-slate-700 shadow-sm'}`}><FiRefreshCcw className="opacity-80" size={14} /> {t('refresh')}</button>
                        <label className="flex items-center gap-1 text-[10px] cursor-pointer select-none">
                          <input type="checkbox" className="accent-emerald-500" checked={detailedMode} onChange={e=>setDetailedMode(e.target.checked)} />
                          <span className="uppercase tracking-wide">Detailed</span>
                        </label>
                        {devicesLoading && <span className="text-xs text-emerald-400 animate-pulse">{t('loading')}</span>}
                      </div>
                      <select
                        value={selectedDevice}
                        onChange={e=>setSelectedDevice(e.target.value)}
                        className={`w-full rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500 border transition ${theme==='dark'
                          ? 'bg-slate-900 border-slate-700 text-slate-100'
                          : 'bg-white border-slate-300 text-slate-800 shadow-sm'} `}
                      >
                        <option value="">-- Select Device --</option>
                        {devices.map(d => {
                          const mockTag = d.id.startsWith('mockfile:') ? ' [MOCK]' : '';
                          const raw = (d && sizeOverrides[d.id] != null) ? sizeOverrides[d.id] : d?.size;
                          let bytesVal = null;
                          if (typeof raw === 'number') {
                            bytesVal = isFinite(raw) ? raw : null;
                          } else if (typeof raw === 'string') {
                            const s = raw.trim();
                            const m = s.match(/^([0-9]+(?:\.[0-9]+)?)\s*(b|bytes|kb|kib|mb|mib|gb|gib)?$/i);
                            if (m) {
                              const num = parseFloat(m[1]);
                              const unit = (m[2] || 'bytes').toLowerCase();
                              const pow2 = { b:1, bytes:1, kib:1024, mib:1024**2, gib:1024**3 };
                              const dec = { kb:1e3, mb:1e6, gb:1e9 };
                              if (unit in pow2) bytesVal = Math.round(num * pow2[unit]);
                              else if (unit in dec) bytesVal = Math.round(num * dec[unit]);
                              else if (/^\d+$/.test(s)) bytesVal = parseInt(s,10);
                            } else if (/^\d+$/.test(s)) {
                              bytesVal = parseInt(s,10);
                            }
                          }
                          let prettySize = '-';
                          let title = '';
                          if (typeof bytesVal === 'number' && !isNaN(bytesVal)) {
                            title = `${bytesVal.toLocaleString()} bytes`;
                            const GiB = 1024*1024*1024;
                            const MiB = 1024*1024;
                            if (bytesVal >= GiB) prettySize = `${(bytesVal / GiB).toFixed(2)} GiB`;
                            else if (bytesVal >= MiB) prettySize = `${Math.round(bytesVal / MiB)} MiB`;
                            else prettySize = `${bytesVal} B`;
                          }
                          return <option key={d.id} value={d.id} title={title}>{d.model}{mockTag} [{d.type}] ({prettySize})</option>;
                        })}
                      </select>
                      {selectedDevice && <div className="mt-3 text-xs text-slate-400">{t('selected')}: <span className="text-emerald-300 font-mono break-all">{selectedDevice}</span></div>}
                      {selectedDevice && (()=>{const d=devices.find(x=>x.id===selectedDevice); if(!d) return null; return (
                        <div className="mt-4 text-[11px] bg-slate-900/60 border border-slate-700 rounded-lg p-3 space-y-1">
                          <div className="text-slate-300 font-semibold mb-1 tracking-wide uppercase text-[10px] flex items-center gap-2">Device Details {d.id.startsWith('mockfile:') && <span className="px-1.5 py-0.5 rounded bg-cyan-700/40 text-cyan-300 text-[9px] font-medium tracking-wider">MOCK</span>}</div>
                          <div className="grid grid-cols-2 gap-x-4 gap-y-1">
                            <span className="text-slate-400">Model</span><span className="text-emerald-300 break-all">{d.model||'-'}</span>
                            <span className="text-slate-400">Type</span><span>{d.type||'-'}</span>
                            <span className="text-slate-400">Size</span>
                            <span>{(()=>{
                              const override = sizeOverrides[d.id];
                              const bytes = (typeof override==='number'&&isFinite(override))? override : (typeof d.size_bytes==='number'&&isFinite(d.size_bytes)? d.size_bytes : parseToBytes(d.size));
                              if (typeof bytes==='number' && isFinite(bytes)) {
                                const GiB = 1024*1024*1024; const MiB = 1024*1024;
                                if (bytes >= GiB) return (bytes/GiB).toFixed(2)+ ' GiB';
                                if (bytes >= MiB) return Math.round(bytes/MiB) + ' MiB';
                                return bytes + ' B';
                              }
                              return '-';
                            })()}</span>
                            {d.serial && <><span className="text-slate-400">Serial</span><span className="break-all">{d.serial}</span></>}
                            {d.interface && <><span className="text-slate-400">Interface</span><span>{d.interface}</span></>}
                            {typeof d.rotational === 'boolean' && <><span className="text-slate-400">Media</span><span>{d.rotational? 'HDD':'SSD/Flash'}</span></>}
                            {d.temperature_c !== undefined && d.temperature_c !== null && <><span className="text-slate-400">Temp</span><span>{d.temperature_c}°C</span></>}
                            {d.health && <><span className="text-slate-400">Health</span><span className={d.health==='PASSED' || d.health==='OK' ? 'text-emerald-400':'text-amber-400'}>{d.health}</span></>}
                            {Array.isArray(d.mountpoints) && d.mountpoints.length>0 && <><span className="text-slate-400">Mounts</span><span>{d.mountpoints.join(',')}</span></>}
                            {d.is_system !== undefined && <><span className="text-slate-400">System Disk</span><span className={d.is_system? 'text-amber-400':'text-emerald-400'}>{String(d.is_system)}</span></>}
                          </div>
                          {/* Low-level capabilities section */}
                          {platformCaps && (
                            <div className="mt-3 text-[10px] rounded bg-slate-800/60 border border-slate-700 p-2">
                              <div className="uppercase tracking-wide text-slate-400 mb-1">Low-level Capabilities</div>
                              <div className="flex flex-wrap gap-2 text-[10px]">
                                <span className={`px-2 py-0.5 rounded ${platformCaps.tools?.hdparm ? 'bg-emerald-900/40 text-emerald-300 border border-emerald-600/40' : 'bg-slate-900/50 text-slate-400 border border-slate-600/40'}`}>hdparm {platformCaps.tools?.hdparm? '✓':'—'}</span>
                                <span className={`px-2 py-0.5 rounded ${platformCaps.tools?.smartctl ? 'bg-emerald-900/40 text-emerald-300 border border-emerald-600/40' : 'bg-slate-900/50 text-slate-400 border border-slate-600/40'}`}>smartctl {platformCaps.tools?.smartctl? '✓':'—'}</span>
                                <span className={`px-2 py-0.5 rounded ${platformCaps.tools?.nvme ? 'bg-emerald-900/40 text-emerald-300 border border-emerald-600/40' : 'bg-slate-900/50 text-slate-400 border border-slate-600/40'}`}>nvme {platformCaps.tools?.nvme? '✓':'—'}</span>
                                {platformCaps.device?.bus_hint && <span className="px-2 py-0.5 rounded bg-cyan-900/40 text-cyan-300 border border-cyan-600/40">bus: {platformCaps.device.bus_hint}</span>}
                              </div>
                              {/* Guidance */}
                              {(() => {
                                const isWin = platformCaps.device?.is_windows_physical;
                                const bus = (platformCaps.device?.bus_hint || '').toLowerCase();
                                if (bus.includes('nvme')) {
                                  return <div className="mt-1 text-slate-400">NVMe device: HPA/DCO not applicable; prefer NVMe sanitize/format (Linux with nvme CLI).</div>;
                                }
                                if (isWin && !platformCaps.tools?.hdparm) {
                                  return <div className="mt-1 text-amber-300">HPA/DCO tools not found on Windows. For full hidden-area clearing, use a Linux environment or vendor utilities.</div>;
                                }
                                if (!isWin && platformCaps.tools?.hdparm) {
                                  return <div className="mt-1 text-slate-400">HPA/DCO clearing can be attempted (hdparm available).</div>;
                                }
                                return null;
                              })()}
                            </div>
                          )}
                          {d.encryption && d.encryption.admin_required && (
                            <div className="mt-2 text-[10px] rounded bg-amber-800/40 border border-amber-600/40 px-2 py-1 text-amber-300 flex items-start gap-2">
                              <span className="mt-0.5">⚠</span>
                              <span>{t('adminPrivilegesNeeded')}</span>
                            </div>
                          )}
                            {isAndroid && (
                              <>
                                {d.android_version && <div className="mt-2 text-[10px] rounded bg-slate-800/60 border border-slate-700 px-2 py-1 text-slate-300 flex justify-between"><span>Android Version</span><span className="text-emerald-300">{d.android_version}</span></div>}
                                {typeof d.android_rooted === 'boolean' && <div className="mt-1 text-[10px] rounded bg-slate-800/60 border border-slate-700 px-2 py-1 text-slate-300 flex justify-between"><span>Root Access</span><span className={d.android_rooted?'text-emerald-300':'text-amber-300'}>{d.android_rooted? 'Yes':'No'}</span></div>}
                              </>
                            )}
                            {isAndroid && d.android_encryption && (
                              <div className="mt-2 text-[10px] rounded bg-slate-800/60 border border-slate-700 px-2 py-1 text-slate-300">
                                <div className="uppercase tracking-wide text-slate-400 mb-1">Android Encryption</div>
                                <div className="grid grid-cols-3 gap-2">
                                  <span>State</span><span className="col-span-2 text-emerald-300">{d.android_encryption.state || '-'}</span>
                                  <span>Type</span><span className="col-span-2">{d.android_encryption.type || '-'}</span>
                                  <span>Status</span><span className="col-span-2">{d.android_encryption.status || '-'}</span>
                                </div>
                                {(!d.android_encryption.state || d.android_encryption.state.toLowerCase() !== 'encrypted') && (
                                  <button type="button" onClick={async()=>{ try { const ser = d.id.split(':')[1]; const r = await fetch(`http://localhost:8000/android_encrypt?serial=${ser}`, { method:'POST'}); const j = await r.json(); alert('Encrypt attempt: '+(j.state||j.status)); fetchDevices(); } catch(e){ alert('Encrypt attempt failed'); } }} className="mt-2 px-2 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-[10px]">Enable Encryption</button>
                                )}
                              </div>
                            )}
                            {d.encryption && d.encryption.volumes && (
                            <details className="mt-2 text-slate-400">
                              <summary className="cursor-pointer">Encryption Volumes ({d.encryption.volumes.length})</summary>
                              <div className="mt-1 max-h-28 overflow-auto space-y-1">
                                {d.encryption.volumes.map((v,i)=>{
                                  const pct = (v.encryption_pct === null || v.encryption_pct === undefined) ? '—' : typeof v.encryption_pct === 'number' ? v.encryption_pct : v.encryption_pct;
                                  const tip = v.details ? JSON.stringify({lock_status:v.lock_status, protection:v.details.ProtectionStatus, pct:v.encryption_pct}, null, 0) : (v.raw_text ? v.raw_text : v.lock_status);
                                  return (
                                    <div key={i} title={tip} className="flex items-center gap-2 bg-slate-800/50 px-2 py-1 rounded">
                                      <span className="flex-1 truncate">{v.mount}</span>
                                      <span className={/unlock/i.test(v.lock_status)?'text-emerald-300':'text-amber-300'}>{v.lock_status}</span>
                                      <span className="text-[10px] rounded bg-slate-900/60 px-1 py-0.5 text-slate-400 min-w-8 text-center">{pct}{pct!=='—' && typeof pct==='number'? '%':''}</span>
                                    </div>
                                  );
                                })}
                              </div>
                            </details>
                          )}
                        </div>
                      )})()}
                      {selectedDevice && smartData && smartData.supported !== false && (
                        <div className="mt-3 space-y-2">
                          {smartData && (
                            <details className="text-slate-300 bg-slate-900/60 p-2 rounded border border-slate-700">
                              <summary className="cursor-pointer text-[11px]">SMART / Health</summary>
                              <div className="mt-2 space-y-1 text-[11px]">
                                {'temperature_c' in smartData && smartData.temperature_c !== null && <div>Temp: <span className="text-emerald-300">{smartData.temperature_c}°C</span></div>}
                                {'health' in smartData && smartData.health && <div>Health: <span className={smartData.health==='PASSED' || smartData.health==='OK' ? 'text-emerald-400':'text-amber-400'}>{smartData.health}</span></div>}
                                {Array.isArray(smartData.interesting_attributes) && smartData.interesting_attributes.length>0 && (
                                  <div className="mt-1">
                                    <div className="text-[10px] uppercase tracking-wide text-slate-400">Attributes</div>
                                    <div className="max-h-32 overflow-auto mt-1 space-y-1">
                                      {smartData.interesting_attributes.map((a,i)=> (
                                        <div key={i} className="flex justify-between gap-2 text-[10px] bg-slate-800/50 px-2 py-1 rounded">
                                          <span>{a.name}</span>
                                          <span className="text-emerald-300">{a.raw?.value ?? a.value ?? '-'}</span>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                {smartData.error && <div className="text-amber-400 text-[10px]">{smartData.error}</div>}
                                {smartData.supported === false && <div className="text-slate-500 text-[10px]">SMART not supported: {smartData.reason}</div>}
                                <details className="mt-2">
                                  <summary className="cursor-pointer text-[10px] text-slate-400">Raw (truncated)</summary>
                                  <pre className="text-[9px] max-h-32 overflow-auto whitespace-pre-wrap">{JSON.stringify(smartData.raw ? (smartData.raw.device? smartData.raw.device: smartData.raw) : smartData, null, 2).slice(0,3000)}</pre>
                                </details>
                              </div>
                            </details>
                          )}
                        </div>
                      )}
                    </SectionCard>
                    <SectionCard title={t('wipeMethod')} icon={FiCpu} className="lg:col-span-1">
                      <select
                        value={method}
                        onChange={e=>setMethod(e.target.value)}
                        className={`w-full rounded px-3 py-2 text-sm border transition ${theme==='dark'
                          ? 'bg-slate-900 border-slate-700 text-slate-100'
                          : 'bg-white border-slate-300 text-slate-800 shadow-sm'} `}
                      >
                        <option value="">-- Select Method --</option>
                        {wipeMethods.filter(m => {
                          // Filter logic:
                          // 1. Hide android_* unless Android device context
                          if(!isAndroid && m.id.startsWith('android_')) return false;
                          if(isAndroid && !['android_root','android_unroot'].includes(m.id)) return false;
                          // 2. Hide mock_* unless a mock device is selected
                          if(!isMock && m.id.startsWith('mock_')) return false;
                          return true;
                        }).map(m => {
                          const labelPrefix = m.id.startsWith('mock_') ? '[MOCK] ' : '';
                          return <option key={m.id} value={m.id}>{labelPrefix}{m.label || m.id} ({m.passes} pass{m.passes>1?'es':''})</option>;
                        })}
                      </select>
                      {isAndroid && method==='android_unroot' && (
                        <div className="mt-2">
                          <label className="block text-[10px] mb-1 text-slate-400 uppercase tracking-wide">Sub Method</label>
                          <select value={subMethod} onChange={e=>setSubMethod(e.target.value)} className={`w-full rounded px-3 py-2 text-sm border transition ${theme==='dark'
                            ? 'bg-slate-900 border-slate-700 text-slate-100'
                            : 'bg-white border-slate-300 text-slate-800 shadow-sm'}`}>
                            <option value="">auto</option>
                            <option value="shunyawipe">shunyawipe</option>
                            <option value="multi-pass">multi-pass</option>
                            <option value="dod_5220_22m">dod_5220_22m</option>
                          </select>
                        </div>
                      )}
                      {methodMeta && (
                        <div className="mt-3 text-xs leading-relaxed text-slate-300 method-meta">
                          <div className="font-medium text-emerald-300 mb-1">{methodMeta.label}</div>
                          <div>{methodMeta.description}</div>
                          <div className="mt-1 flex gap-2 flex-wrap">
                            <Pill>{methodMeta.passes} pass{methodMeta.passes>1?'es':''}</Pill>
                            <Pill tone='cyan'>Energy:{Math.round((methodMeta.energy_factor||1)*100)}%</Pill>
                          </div>
                        </div>
                      )}
                    </SectionCard>
                    <SectionCard title={t('preconditions')} icon={FiLock} className="lg:col-span-1 space-y-4">
                      {isMock && (
                        <div className="text-[10px] rounded bg-cyan-900/40 border border-cyan-600/40 p-2 leading-relaxed text-cyan-200">
                          <div className="font-semibold mb-1 tracking-wide flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"/>Mock Mode Active</div>
                          Operations run against a synthetic file sandbox. No real hardware data is affected. Use this to validate workflow, certificates, and verification logic safely.
                        </div>
                      )}
                      {isAndroid && (
                        <div className="space-y-2">
                          <h4 className="text-sm font-semibold text-cyan-300">{t('androidChecklist')}</h4>
                          {['adb','connected','encrypted'].map(key => (
                            <label key={key} className="flex items-center gap-2 text-xs">
                              <input type="checkbox" className="accent-emerald-500" checked={checklist[key]} onChange={e=>setChecklist(c=>({...c,[key]:e.target.checked}))}/>
                              <span className="capitalize">{key}</span>
                            </label>
                          ))}
                          <div className="text-[10px] text-slate-400 mt-1">Encryption status: <span className="text-emerald-300">{androidEncryption || '...'}</span></div>
                        </div>
                      )}
                      {isWindowsDrive && (
                        <div className="space-y-2">
                          <h4 className="text-sm font-semibold text-cyan-300">{t('windowsBitlocker')}</h4>
                          <div className="text-xs">{t('status')}: <span className="text-emerald-300">{winBitLocker.status || '...'}</span></div>
                          <div className="flex flex-wrap gap-2">
                            {winBitLocker.details.filter(r=>r.status==='Locked').map(r => (
                              <button key={r.drive} onClick={()=>setUnlockModal({ open:true, drive:r.drive, method:'password', value:'' })} className="px-2 py-1 text-[10px] rounded bg-amber-600/70 hover:bg-amber-600">Unlock {r.drive}</button>
                            ))}
                          </div>
                          <details className="text-slate-400 text-[10px]">
                            <summary className="cursor-pointer mt-1">Debug: Raw BitLocker Response</summary>
                            <div className="mt-2 space-y-1">
                              <button type="button" onClick={()=>{
                                const url = `http://localhost:8000/bitlocker_status?device_id=${encodeURIComponent(selectedDevice)}`;
                                fetch(url).then(r=>r.json()).then(d=>{ setBitlockerRaw(d); }).catch(e=> setBitlockerRaw({ error:String(e)}));
                              }} className="px-2 py-1 rounded bg-slate-700 hover:bg-slate-600 text-[10px]">Refresh</button>
                              <pre className="max-h-40 overflow-auto bg-slate-900/70 p-2 rounded border border-slate-700 whitespace-pre-wrap">{bitlockerRaw? JSON.stringify(bitlockerRaw,null,2):'No data yet'}</pre>
                            </div>
                          </details>
                        </div>
                      )}
                      {!isAndroid && !isWindowsDrive && <p className="text-xs text-slate-400">{t('noSpecial')}</p>}
                      <button disabled={disableErase} onClick={startErase} className={`w-full mt-4 px-4 py-2 rounded font-medium text-sm transition flex items-center justify-center gap-2 ${disableErase? 'bg-slate-700 text-slate-400 cursor-not-allowed':'bg-gradient-to-r from-emerald-600 to-cyan-600 text-white hover:brightness-110 shadow pulse-ring'} `}>{erasing? <><FiZap className="animate-pulse" /> {t('erasing')}</> : <><FiPlay /> {t('startErase')}</>}</button>
                      {erasing && <div className="text-[10px] text-emerald-400 animate-pulse">{t('doNotDisconnect')}</div>}
                    </SectionCard>
                  </div>
                )}

                {activeTab==='progress' && (
                  <div className="grid lg:grid-cols-3 gap-6">
                    <SectionCard title={t('realTimeProgress')} className="lg:col-span-2">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2 text-[10px]">
                          {(()=>{ const wc = progress.filter(l=>/(fail|error)/i.test(l)).length; return (
                            <span className={`px-2 py-0.5 rounded ${wc? 'bg-amber-900/40 text-amber-300 border border-amber-600/40':'bg-emerald-900/40 text-emerald-300 border border-emerald-600/40'}`}>Warnings: {wc}</span>
                          ); })()}
                        </div>
                        <label className="flex items-center gap-2 text-[10px]">
                          <input type="checkbox" className="accent-emerald-500" checked={showOnlyWarnings} onChange={e=>setShowOnlyWarnings(e.target.checked)} />
                          <span>Show only warnings</span>
                        </label>
                      </div>
                      <pre className="text-[11px] leading-snug max-h-[50vh] overflow-auto font-mono whitespace-pre-wrap">{(showOnlyWarnings? progress.filter(l=>/(fail|error)/i.test(l)): progress).join('\n') || t('noActivity')}</pre>
                      <div className="mt-2 flex justify-end">
                        <button onClick={()=>window.open(`http://localhost:8000/logs_export?device_id=${encodeURIComponent(selectedDevice)}`, '_blank')} className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-600 text-[10px]">Download Full Logs</button>
                      </div>
                    </SectionCard>
                    <SectionCard title="Detailed Metrics" className="lg:col-span-1">
                      {!detailedProgress && <div className="text-xs text-slate-400">Awaiting progress...</div>}
                      {detailedProgress && (
                        <div className="space-y-4 text-xs">
                          <div className="flex justify-between"><span>Status</span><span className="font-medium text-emerald-300">{detailedProgress.status}</span></div>
                          <div className="flex justify-between"><span>Pass</span><span>{Math.min(detailedProgress.pass_index, detailedProgress.passes_total)}/{detailedProgress.passes_total}{detailedProgress.current_pattern?` (${detailedProgress.current_pattern})`:''}</span></div>
                          <div className="flex justify-between"><span>Bytes</span><span>{(detailedProgress.bytes_written/1e9).toFixed(2)} / {(detailedProgress.total_bytes/1e9).toFixed(2)} GB</span></div>
                          <div className="flex justify-between"><span>Percent</span><span>{detailedProgress.total_bytes? ((detailedProgress.bytes_written/detailedProgress.total_bytes)*100).toFixed(1):'0'}%</span></div>
                          <div className="flex justify-between"><span>Speed</span><span>{detailedProgress._speedMBs? detailedProgress._speedMBs.toFixed(1):'0.0'} MB/s</span></div>
                          {detailedProgress._etaSec !== null && <div className="flex justify-between"><span>ETA</span><span>{detailedProgress._etaSec>7200?'>2h': detailedProgress._etaSec>3600?'>1h': new Date(detailedProgress._etaSec*1000).toISOString().substr(11,8)}</span></div>}
                          {/* Visual progress bar */}
                          <div className="space-y-1">
                            <div className="h-2.5 w-full rounded bg-slate-700 overflow-hidden flex">
                              {Array.from({length: detailedProgress.passes_total}).map((_,i)=>{
                                const isDone = i < (detailedProgress.pass_index||0);
                                const isCurrent = i === (detailedProgress.pass_index||0);
                                const patternLabel = detailedProgress.pass_patterns && detailedProgress.pass_patterns[i] ? detailedProgress.pass_patterns[i] : '';
                                const title = isDone? `Pass ${i+1} ${patternLabel} complete` : isCurrent? `Pass ${i+1} ${patternLabel} active` : `Pass ${i+1} ${patternLabel} pending`;
                                return <div key={i} title={title} className={`h-full transition-all duration-300 ${isDone? 'bg-emerald-500': isCurrent? 'bg-cyan-500 animate-pulse':'bg-slate-600/60'}`} style={{flex:1, marginRight: i===detailedProgress.passes_total-1?0:2, opacity: isCurrent?1: undefined}} />
                              })}
                            </div>
                            <div className="flex justify-between text-[10px] tracking-wide uppercase text-slate-400">
                              <span>Pass Segments</span>
                              {detailedProgress.total_bytes ? (
                                <span>{((detailedProgress.bytes_written/detailedProgress.total_bytes)*100).toFixed(1)}%</span>
                              ): <span>0%</span>}
                            </div>
                          </div>
                          {detailedProgress.verified !== null && <div className="flex justify-between"><span>Verified</span><span className={detailedProgress.verified? 'text-emerald-400':'text-amber-400'}>{String(detailedProgress.verified)}</span></div>}
                          {detailedProgress.completed_at && <div className="flex justify-between"><span>Completed</span><span>{new Date(detailedProgress.completed_at).toLocaleTimeString()}</span></div>}
                          {(!detailedProgress.completed_at && detailedProgress.status !== 'cancelled') && (
                            <button onClick={async()=>{ try { await axios.post('http://localhost:8000/cancel', null, { params:{ device_id: selectedDevice }});} catch(e){} }} className="w-full mt-2 px-2 py-1.5 rounded bg-amber-600 hover:bg-amber-500 text-[11px] font-medium">Cancel</button>
                          )}
                          {detailedProgress && detailedProgress.status==='running' && !erasing && (
                            <button onClick={async()=>{ try { await axios.post('http://localhost:8000/erase?confirm=true', { device_id: selectedDevice, method: detailedProgress.method, resume: true }); setProgress(p=>[...p,'Resume requested...']); } catch { setProgress(p=>[...p,'Resume failed']); } }} className="w-full mt-2 px-2 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-[11px] font-medium">Resume</button>
                          )}
                        </div>
                      )}
                    </SectionCard>
                  </div>
                )}

                {activeTab==='certificates' && (
                  <CertificatesList t={t} />
                )}
              </main>

              {unlockModal.open && (
                <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
                  <div className="w-full max-w-md bg-slate-900 border border-slate-700 rounded-xl p-6 shadow-xl">
                    <h3 className="text-lg font-semibold mb-4 eco-gradient-text">Unlock BitLocker ({unlockModal.drive})</h3>
                    <label className="block text-xs mb-2 font-medium">Method</label>
                    <select value={unlockModal.method} onChange={e=>setUnlockModal(m=>({...m, method:e.target.value, value:''}))} className="w-full bg-slate-800 border border-slate-600 rounded px-3 py-2 text-sm mb-4">
                      <option value="password">Password</option>
                      <option value="recovery_key">Recovery Key</option>
                      <option value="numerical_password">Numerical Password</option>
                      <option value="key_file">Key File (.BEK)</option>
                    </select>
                    <label className="block text-xs mb-2 font-medium">{unlockModal.method === 'key_file' ? 'Key File Path' : 'Value'}</label>
                    <input value={unlockModal.value} onChange={e=>setUnlockModal(m=>({...m,value:e.target.value}))} placeholder={unlockModal.method==='key_file'? 'C:\\path\\to\\keyfile.BEK':'Enter value'} className="w-full bg-slate-800 border border-slate-600 rounded px-3 py-2 text-sm mb-5" />
                    <div className="flex gap-3">
                      <button onClick={async ()=>{
                        if(!unlockModal.value.trim()) return alert('Enter a value');
                        const body = { device_id: unlockModal.drive, [unlockModal.method]: unlockModal.value };
                        try {
                          const res = await fetch('http://localhost:8000/bitlocker_unlock',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
                          const data = await res.json();
                          if(data.status==='Unlocked') {
                            setWinBitLocker(w=>({...w, status: w.status?.replace(`${unlockModal.drive}: Locked`, `${unlockModal.drive}: Unlocked`)}));
                            setUnlockModal({ open:false, drive:'', method:'password', value:''});
                          } else alert('Unlock failed');
                        } catch(e){ alert('Unlock failed'); }
                      }} className="px-4 py-2 rounded bg-emerald-600 hover:bg-emerald-500 text-sm font-medium">Unlock</button>
                      <button onClick={()=>setUnlockModal({ open:false, drive:'', method:'password', value:''})} className="px-4 py-2 rounded bg-slate-700 hover:bg-slate-600 text-sm">Cancel</button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
}

function CertificatesList({ t = (k)=>k }){
  const [certs, setCerts] = useState([]);
  const [loading, setLoading] = useState(true);
  useEffect(()=>{ fetch('http://localhost:8000/certificates').then(r=>r.json()).then(d=>{setCerts(d); setLoading(false);}).catch(()=>setLoading(false)); },[]);
  if (loading) return <SectionCard title={t('certificatesTab')}>{t('loading')}</SectionCard>;
  if (!certs.length) return <SectionCard title={t('certificatesTab')}>{t('noCertificates') || 'No certificates yet.'}</SectionCard>;
  return (
  <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-6">
      {certs.map(c => (
        <div key={c.log_hash || c.device_id} className="eco-card border border-slate-700/70">
          <div className="flex items-center justify-between mb-2">
            <h4 className="font-semibold text-sm text-emerald-300 truncate">{c.device_id}</h4>
            <Pill tone='cyan'>{c.method}</Pill>
          </div>
          <div className="text-[11px] space-y-1 text-slate-300">
      <div>{t('trust') || 'Trust'}: <span className="text-emerald-400 font-medium">{c.trust_score}</span></div>
      <div>Passes: {c.passes}</div>
      {c.eco?.ewaste_kg_risk_reduced !== undefined && <div>Eco: {c.eco.ewaste_kg_risk_reduced} kg reduced</div>}
      {c.eco?.energy_kwh_est !== undefined && <div>{t('energy')}: {c.eco.energy_kwh_est ?? '-'} kWh</div>}
      {c.eco?.co2_kg_est !== undefined && <div>{t('carbon')}: {c.eco.co2_kg_est ?? '-'} kg</div>}
      <div className="truncate">Hash: {c.log_hash?.slice(0,20)}...</div>
            <div className="pt-2 flex flex-wrap gap-2">
              <button
                type="button"
                onClick={()=>window.open(`http://localhost:8000/certificate?device_id=${encodeURIComponent(c.device_id)}&format=json`, '_blank')}
                className="px-2 py-1 rounded bg-slate-800/60 hover:bg-slate-700 text-[10px] border border-slate-600"
              >View JSON</button>
              <button
                type="button"
                onClick={()=>window.open(`http://localhost:8000/certificate?device_id=${encodeURIComponent(c.device_id)}&format=pdf`, '_blank')}
                className="px-2 py-1 rounded bg-slate-800/60 hover:bg-slate-700 text-[10px] border border-slate-600"
              >PDF</button>
              <button
                type="button"
                onClick={()=>window.open(`http://localhost:8000/certificate_export?device_id=${encodeURIComponent(c.device_id)}`, '_blank')}
                className="px-2 py-1 rounded bg-slate-800/60 hover:bg-slate-700 text-[10px] border border-slate-600"
              >Bundle</button>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// Ensure default export (was removed during refactor)
export default App;
