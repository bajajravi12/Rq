/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Terminal, Shield, Search, FileText, Play, Pause, Square, Save, Download, AlertCircle, ChevronRight, Activity, LogOut } from 'lucide-react';

// --- Types ---
interface Hit {
  target: string;
  server: string;
  status: string;
  method: string;
  version: string;
  time: number;
}

interface ScanState {
  scanId: string | null;
  progress: number;
  hits: Hit[];
  status: 'idle' | 'running' | 'paused' | 'completed' | 'stopped';
  current: number;
  total: number;
}

// --- Components ---

const Header = () => (
  <div className="mb-6 relative overflow-hidden group">
    <div className="absolute -inset-1 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-lg blur opacity-25 group-hover:opacity-50 transition duration-1000"></div>
    <pre className="relative text-[0.6rem] leading-none text-cyan-400 font-mono font-bold mb-2 select-none overflow-hidden whitespace-pre animate-pulse">
      {`
 ╔══════════════════════════════════════════╗
 ║   ██████╗  █████╗ ██╗   ██╗ █████╗ ███╗  ║
 ║   ██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗ ║
 ║   ██████╔╝███████║██║   ██║███████║██╔██╗║
 ║   ██╔══██╗██╔══██║╚██╗ ██╔╝██╔══██║██║╚██║
 ║   ██║  ██║██║  ██║ ╚████╔╝ ██║  ██║██║ ██║
 ║   ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝╚═╝ ╚═╝
 ║         INFRA TERMINAL | By RQ           ║
 ╚══════════════════════════════════════════╝
      `}
    </pre>
    <div className="flex items-center gap-2 text-xs font-mono relative">
      <span className="bg-cyan-500 text-black px-1 font-bold shadow-[0_0_10px_rgba(6,182,212,0.5)]">RQ ACTIVE</span>
      <span className="text-zinc-500">v2.0.0</span>
      <span className="text-zinc-500 ml-auto">PRO TERMINAL</span>
    </div>
  </div>
);

const HitPanel: React.FC<{ hit: Hit }> = ({ hit }) => (
  <motion.div
    initial={{ opacity: 0, scale: 0.95 }}
    animate={{ opacity: 1, scale: 1 }}
    className="mb-4 font-mono text-[0.7rem] w-full border border-cyan-900/50 bg-black/40 backdrop-blur-sm shadow-lg shadow-cyan-500/5"
  >
    <div className="bg-cyan-950/30 px-2 py-0.5 border-b border-cyan-900/50 text-cyan-400 flex justify-between uppercase font-bold text-[0.6rem]">
      <span>✓ SCAN RESULT</span>
      <span>{hit.time}ms</span>
    </div>
    <div className="p-2 space-y-1">
      <div className="flex items-center gap-2">
        <span className="w-16 text-zinc-500">HOST</span>
        <span className="text-white truncate font-bold">{hit.target}</span>
      </div>
      <div className="flex items-center gap-2">
        <span className="w-16 text-zinc-500">SERVER</span>
        <span className="text-cyan-300">{hit.server}</span>
      </div>
      <div className="flex items-center gap-2">
        <span className="w-16 text-zinc-500">TLS</span>
        <span className="text-blue-400">TLS 1.3</span>
      </div>
      <div className="flex items-center gap-2">
        <span className="w-16 text-zinc-500">SIGNAL</span>
        <span className="text-spring-green-400 flex items-center gap-1">
          <Activity className="w-3 h-3 animate-pulse" /> RESPONSIVE
        </span>
      </div>
    </div>
  </motion.div>
);

// --- Constants ---
const menuOptions = [
  { id: 1, label: 'SINGLE INSPECTOR', icon: Search },
  { id: 2, label: 'CIDR INVENTORY', icon: Terminal },
  { id: 3, label: 'BULK ASSET AUDIT', icon: FileText },
  { id: 4, label: 'METHOD ANALYZER', icon: Activity },
  { id: 5, label: 'REVERSE DNS PRO', icon: Shield },
  { id: 6, label: 'VIEW LOGS', icon: Save },
  { id: 7, label: 'SETTINGS', icon: Activity },
  { id: 8, label: 'EXIT', icon: LogOut },
];

export default function App() {
  const [activeMenu, setActiveMenu] = useState<number | null>(null);
  const [inputVal, setInputVal] = useState('');
  const [ports, setPorts] = useState('80,443');
  const [scan, setScan] = useState<ScanState>({
    scanId: null,
    progress: 0,
    hits: [],
    status: 'idle',
    current: 0,
    total: 0
  });

  const timerRef = useRef<NodeJS.Timeout | null>(null);
  const consoleRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
    }
  }, [scan.hits]);

  const startScan = async () => {
    if (!inputVal) return;
    
    try {
      const res = await fetch('/api/scan/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: activeMenu === 1 || activeMenu === 3 ? 'FILE' : 'CIDR',
          target: inputVal,
          ports: ports.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p))
        })
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      
      setScan(prev => ({ ...prev, scanId: data.scanId, status: 'running', hits: [], progress: 0 }));
      pollScan(data.scanId);
    } catch (err: any) {
      alert(err.message);
    }
  };

  const pollScan = (id: string) => {
    timerRef.current = setInterval(async () => {
      try {
        const res = await fetch(`/api/scan/${id}`);
        const data = await res.json();
        setScan(prev => ({
          ...prev,
          progress: data.progress,
          hits: data.hits,
          status: data.status,
          current: data.current,
          total: data.total
        }));
        if (data.status === 'completed' || data.status === 'stopped') {
          if (timerRef.current) clearInterval(timerRef.current);
        }
      } catch (e) {
        if (timerRef.current) clearInterval(timerRef.current);
      }
    }, 1000);
  };

  const controlScan = async (action: 'pause' | 'resume' | 'stop') => {
    if (!scan.scanId) return;
    await fetch(`/api/scan/${scan.scanId}/control`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action })
    });
    setScan(prev => ({ ...prev, status: action === 'pause' ? 'paused' : action === 'resume' ? 'running' : 'stopped' }));
  };

  const reset = () => {
    setActiveMenu(null);
    setInputVal('');
    setScan({ scanId: null, progress: 0, hits: [], status: 'idle', current: 0, total: 0 });
    if (timerRef.current) clearInterval(timerRef.current);
  };

  return (
    <div className="min-h-screen bg-black text-white font-mono p-4 flex flex-col items-center">
      <div className="w-full max-w-[400px]">
        <Header />

        <AnimatePresence mode="wait">
          {activeMenu === null ? (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="grid grid-cols-1 gap-2"
            >
              {menuOptions.map((opt) => (
                <button 
                  key={opt.id}
                  onClick={() => setActiveMenu(opt.id)}
                  className="w-full group flex items-center gap-3 p-2.5 bg-zinc-900/50 border border-zinc-800 hover:border-cyan-500 hover:bg-cyan-950/20 transition-all text-left"
                >
                  <span className="text-cyan-500 font-bold w-6">[{opt.id}]</span>
                  <span className="flex-1 text-[0.7rem] font-bold tracking-wider">{opt.label}</span>
                  <opt.icon className="w-4 h-4 text-zinc-700 group-hover:text-cyan-400 group-hover:drop-shadow-[0_0_5px_rgba(6,182,212,0.5)]" />
                </button>
              ))}
              
              <div className="mt-4 pt-4 border-t border-zinc-900">
                <div className="text-[0.6rem] text-zinc-600 mb-2 uppercase tracking-widest">System Architecture</div>
                <div className="flex gap-2">
                  <div className="text-[0.55rem] bg-zinc-900 border border-zinc-800 px-2 py-1 flex items-center gap-1 text-zinc-400">
                    <Activity className="w-3 h-3 text-cyan-500" /> AIOHTTP CORE
                  </div>
                  <div className="text-[0.55rem] bg-zinc-900 border border-zinc-800 px-2 py-1 flex items-center gap-1 text-zinc-400">
                    <Shield className="w-3 h-3 text-blue-500" /> TLS 1.3
                  </div>
                </div>
              </div>
            </motion.div>
          ) : scan.status === 'idle' ? (
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              className="space-y-4"
            >
              <div className="flex items-center gap-2 text-[0.6rem] text-cyan-500 mb-4 font-bold">
                <span onClick={reset} className="cursor-pointer hover:text-cyan-300">MENU</span>
                <ChevronRight className="w-3 h-3" />
                <span className="text-white uppercase">{menuOptions.find(o => o.id === activeMenu)?.label}</span>
              </div>

              <div className="space-y-4 p-4 border border-zinc-800 bg-zinc-950/50">
                <div>
                  <label className="text-[0.6rem] text-zinc-500 mb-1 block uppercase tracking-wider">Input Target</label>
                  <input
                    type="text"
                    value={inputVal}
                    onChange={(e) => setInputVal(e.target.value)}
                    placeholder={activeMenu === 2 ? "192.168.1.0/24" : "google.com, example.com"}
                    className="w-full bg-black border border-zinc-800 p-2 text-xs outline-none focus:border-cyan-500 text-cyan-50 transition-colors"
                  />
                </div>
                <div>
                  <label className="text-[0.6rem] text-zinc-500 mb-1 block uppercase tracking-wider">Parameters</label>
                  <input
                    type="text"
                    value={ports}
                    onChange={(e) => setPorts(e.target.value)}
                    className="w-full bg-black border border-zinc-800 p-2 text-xs outline-none focus:border-cyan-500 text-zinc-400"
                  />
                </div>
                <button
                  onClick={startScan}
                  className="w-full bg-cyan-600 text-black py-2 font-black text-xs hover:bg-cyan-400 transition-all flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(6,182,212,0.3)]"
                >
                  <Play className="w-3 h-3" /> INITIALIZE SCAN
                </button>
              </div>
            </motion.div>
          ) : (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="space-y-4"
            >
              {/* Active Scanner UI */}
              <div className="bg-black border border-cyan-900 p-4 font-mono shadow-[0_0_20px_rgba(6,182,212,0.05)]">
                <div className="flex items-center justify-between mb-4 border-b border-cyan-950/50 pb-2">
                  <div className="flex items-center gap-2">
                    <Activity className={`w-3 h-3 ${scan.status === 'running' ? 'text-cyan-400 animate-pulse' : 'text-zinc-600'}`} />
                    <span className="text-[0.6rem] text-cyan-500 font-bold tracking-widest uppercase">RQ Terminal Active</span>
                  </div>
                  <div className="text-[0.55rem] text-zinc-500 font-bold">
                    HUTS: {scan.hits.length} / TARGETS: {scan.total}
                  </div>
                </div>

                <div className="mb-4">
                  <div className="text-[0.6rem] text-zinc-500 mb-1 truncate opacity-50">{inputVal}</div>
                  <div className="h-1 bg-zinc-900 w-full overflow-hidden">
                    <motion.div 
                      className="h-full bg-cyan-500 shadow-[0_0_5px_rgba(6,182,212,0.8)]" 
                      animate={{ width: `${scan.progress}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-[0.55rem] mt-1 font-bold">
                    <span className="text-cyan-500">{scan.progress}% COMPLETION</span>
                    <span className={`uppercase ${scan.status === 'running' ? 'text-green-500' : 'text-yellow-500'}`}>{scan.status}</span>
                  </div>
                </div>

                <div className="flex gap-2">
                  {scan.status === 'running' && (
                    <button onClick={() => controlScan('pause')} className="flex-1 bg-zinc-950 border border-zinc-900 py-1.5 text-[0.6rem] hover:bg-zinc-900 flex items-center justify-center gap-1 font-bold">
                      <Pause className="w-3 h-3" /> PAUSE
                    </button>
                  )}
                  {scan.status === 'paused' && (
                    <button onClick={() => controlScan('resume')} className="flex-1 bg-zinc-950 border border-zinc-900 py-1.5 text-[0.6rem] hover:bg-zinc-900 flex items-center justify-center gap-1 font-bold">
                      <Play className="w-3 h-3" /> RESUME
                    </button>
                  )}
                  {(scan.status === 'running' || scan.status === 'paused') && (
                    <button onClick={() => controlScan('stop')} className="flex-1 bg-zinc-950 border border-zinc-900 py-1.5 text-[0.6rem] hover:border-red-900 hover:text-red-500 flex items-center justify-center gap-1 font-bold text-zinc-400">
                      <Square className="w-3 h-3" /> ABORT
                    </button>
                  )}
                  {(scan.status === 'completed' || scan.status === 'stopped') && (
                    <button onClick={reset} className="flex-1 bg-cyan-600 text-black py-1.5 text-[0.6rem] hover:bg-cyan-400 flex items-center justify-center gap-1 font-black shadow-[0_0_10px_rgba(6,182,212,0.4)]">
                      <Save className="w-3 h-3" /> LOG RESULTS & EXIT
                    </button>
                  )}
                </div>
              </div>

              {/* Console / Hits List */}
              <div 
                ref={consoleRef}
                className="h-[320px] overflow-y-auto border-t border-zinc-900 pt-4 scrollbar-hide flex flex-col gap-2"
              >
                {scan.hits.map((hit, i) => (
                  <HitPanel key={i} hit={hit} />
                ))}
                {scan.hits.length === 0 && scan.status === 'running' && (
                  <div className="flex flex-col items-center justify-center h-full gap-2 py-20">
                    <Activity className="w-6 h-6 text-zinc-900 animate-pulse" />
                    <div className="text-zinc-800 text-[0.55rem] font-bold tracking-[0.2em] uppercase">
                      HUNTING ASSETS...
                    </div>
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
      
      {/* Absolute Bottom Info */}
      <div className="fixed bottom-4 left-4 right-4 flex justify-between items-center text-[0.55rem] text-zinc-800 pointer-events-none uppercase tracking-widest font-black">
        <span>AUTHORITY VERIFIED</span>
        <span className="flex items-center gap-1"><Shield className="w-3 h-3" /> CYBER SEC CORE</span>
      </div>
    </div>
  );
}

