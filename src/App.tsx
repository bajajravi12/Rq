/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Terminal, Shield, Search, FileText, Play, Pause, Square, Save, Download, AlertCircle, ChevronRight, Activity } from 'lucide-react';

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
  <div className="mb-6">
    <pre className="text-[0.6rem] leading-none text-red-500 font-mono font-bold mb-2 select-none overflow-hidden whitespace-pre">
      {`
    ██████╗  █████╗ ██╗   ██╗ █████╗ ███╗   ██╗
    ██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║
    ██████╔╝███████║██║   ██║███████║██╔██╗ ██║
    ██╔══██╗██╔══██║╚██╗ ██╔╝██╔══██║██║╚██╗██║
    ██║  ██║██║  ██║ ╚████╔╝ ██║  ██║██║ ╚████║
    ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝
      `}
    </pre>
    <div className="flex items-center gap-2 text-xs font-mono">
      <span className="bg-red-500 text-black px-1 font-bold">INFRA-X LITE</span>
      <span className="text-zinc-500">v1.0.0</span>
      <span className="text-zinc-500 ml-auto">Termux Optimized</span>
    </div>
  </div>
);

const HitPanel = ({ hit }: { hit: Hit }) => (
  <motion.div
    initial={{ opacity: 0, x: -10 }}
    animate={{ opacity: 1, x: 0 }}
    className="mb-4 font-mono text-xs w-full max-w-[320px]"
  >
    <div className="text-red-500">╭──── HIT ────╮</div>
    <div className="flex px-2 border-l border-red-500 py-0.5">
      <span className="w-16 text-zinc-400">Proxy</span>
      <span className="text-white truncate">{hit.target}</span>
    </div>
    <div className="flex px-2 border-l border-red-500 py-0.5">
      <span className="w-16 text-zinc-400">Server</span>
      <span className="text-white">{hit.server}</span>
    </div>
    <div className="flex px-2 border-l border-red-500 py-0.5">
      <span className="w-16 text-zinc-400">Status</span>
      <span className="text-white">{hit.status}</span>
    </div>
    <div className="flex px-2 border-l border-red-500 py-0.5">
      <span className="w-16 text-zinc-400">Method</span>
      <span className="text-white">{hit.method}</span>
    </div>
    <div className="flex px-2 border-l border-red-500 py-0.5">
      <span className="w-16 text-zinc-400">Signal</span>
      <span className="text-green-500">Responsive</span>
    </div>
    <div className="flex px-2 border-l border-red-500 py-0.5">
      <span className="w-16 text-zinc-400">Version</span>
      <span className="text-white">{hit.version}</span>
    </div>
    <div className="text-red-500">╰─────────────╯</div>
  </motion.div>
);

export default function App() {
  const [mode, setMode] = useState<1 | 2 | null>(null);
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
          mode: mode === 1 ? 'FILE' : 'CIDR',
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
    setMode(null);
    setInputVal('');
    setScan({ scanId: null, progress: 0, hits: [], status: 'idle', current: 0, total: 0 });
    if (timerRef.current) clearInterval(timerRef.current);
  };

  return (
    <div className="min-h-screen bg-black text-white font-mono p-4 flex flex-col items-center">
      <div className="w-full max-w-[400px]">
        <Header />

        <AnimatePresence mode="wait">
          {mode === null ? (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="space-y-4"
            >
              <button 
                onClick={() => setMode(1)}
                className="w-full group flex items-center gap-3 p-3 bg-zinc-900 border border-zinc-800 hover:border-red-500 transition-colors text-left"
              >
                <span className="text-red-500 font-bold">[1]</span>
                <span className="flex-1">FILE SCAN</span>
                <ChevronRight className="w-4 h-4 text-zinc-700 group-hover:text-red-500" />
              </button>
              <button 
                onClick={() => setMode(2)}
                className="w-full group flex items-center gap-3 p-3 bg-zinc-900 border border-zinc-800 hover:border-red-500 transition-colors text-left"
              >
                <span className="text-red-500 font-bold">[2]</span>
                <span className="flex-1">CIDR SCAN</span>
                <ChevronRight className="w-4 h-4 text-zinc-700 group-hover:text-red-500" />
              </button>
              
              <div className="pt-8 border-t border-zinc-900">
                <div className="text-[0.7rem] text-zinc-500 mb-2">DEVELOPER ACCESS</div>
                <div className="flex flex-wrap gap-2">
                  <a href="/pyproject.toml" download className="text-[0.6rem] bg-zinc-800 px-2 py-1 flex items-center gap-1 hover:bg-zinc-700">
                    <Download className="w-3 h-3" /> PIP INSTALL
                  </a>
                  <div className="text-[0.6rem] bg-zinc-800 px-2 py-1 text-zinc-400">
                    PYTHON 3.13+ REQ
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
              <div className="flex items-center gap-2 text-xs text-red-500 mb-4">
                <span onClick={reset} className="cursor-pointer hover:underline">MENU</span>
                <ChevronRight className="w-3 h-3" />
                <span className="text-white uppercase">{mode === 1 ? 'File Scan' : 'CIDR Scan'}</span>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="text-[0.7rem] text-zinc-500 mb-1 block">TARGET {mode === 1 ? 'LIST (comma-separated)' : 'CIDR (max /24 for demo)'}</label>
                  <input
                    type="text"
                    value={inputVal}
                    onChange={(e) => setInputVal(e.target.value)}
                    placeholder={mode === 1 ? "google.com, example.com" : "192.168.1.0/24"}
                    className="w-full bg-zinc-900 border border-zinc-800 p-2 text-sm outline-none focus:border-red-500"
                  />
                </div>
                <div>
                  <label className="text-[0.7rem] text-zinc-500 mb-1 block">PORTS (comma-separated)</label>
                  <input
                    type="text"
                    value={ports}
                    onChange={(e) => setPorts(e.target.value)}
                    className="w-full bg-zinc-900 border border-zinc-800 p-2 text-sm outline-none focus:border-red-500"
                  />
                </div>
                <button
                  onClick={startScan}
                  className="w-full bg-red-500 text-black py-2 font-bold hover:bg-red-400 transition-colors flex items-center justify-center gap-2"
                >
                  <Play className="w-4 h-4" /> START HUNT
                </button>
              </div>
            </motion.div>
          ) : (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="space-y-6"
            >
              {/* Active Scanner UI */}
              <div className="bg-zinc-950 border border-zinc-900 p-4 font-mono">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <Activity className={`w-4 h-4 ${scan.status === 'running' ? 'text-green-500 animate-pulse' : 'text-zinc-500'}`} />
                    <span className="text-xs text-red-500 font-bold">『 HUNTER ACTIVE 』</span>
                  </div>
                  <div className="text-[0.6rem] text-zinc-500">
                    H:{scan.hits.length} / T:{scan.total}
                  </div>
                </div>

                <div className="mb-4">
                  <div className="text-[0.6rem] text-zinc-400 mb-1 truncate">{inputVal}</div>
                  <div className="h-2 bg-zinc-900 w-full overflow-hidden">
                    <motion.div 
                      className="h-full bg-red-500" 
                      animate={{ width: `${scan.progress}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-[0.6rem] mt-1">
                    <span className="text-red-500">{scan.progress}%</span>
                    <span className="text-zinc-500 uppercase">{scan.status}</span>
                  </div>
                </div>

                <div className="flex gap-2">
                  {scan.status === 'running' && (
                    <button onClick={() => controlScan('pause')} className="flex-1 bg-zinc-900 border border-zinc-800 py-1 text-[0.7rem] hover:bg-zinc-800 flex items-center justify-center gap-1">
                      <Pause className="w-3 h-3" /> PAUSE
                    </button>
                  )}
                  {scan.status === 'paused' && (
                    <button onClick={() => controlScan('resume')} className="flex-1 bg-zinc-900 border border-zinc-800 py-1 text-[0.7rem] hover:bg-zinc-800 flex items-center justify-center gap-1">
                      <Play className="w-3 h-3" /> RESUME
                    </button>
                  )}
                  {(scan.status === 'running' || scan.status === 'paused') && (
                    <button onClick={() => controlScan('stop')} className="flex-1 bg-zinc-900 border border-zinc-800 py-1 text-[0.7rem] hover:bg-zinc-800 flex items-center justify-center gap-1">
                      <Square className="w-3 h-3" /> QUIT
                    </button>
                  )}
                  {(scan.status === 'completed' || scan.status === 'stopped') && (
                    <button onClick={reset} className="flex-1 bg-red-500 text-black py-1 text-[0.7rem] hover:bg-red-400 flex items-center justify-center gap-1 font-bold">
                      <Save className="w-3 h-3" /> SAVE & EXIT
                    </button>
                  )}
                </div>
              </div>

              {/* Console / Hits List */}
              <div 
                ref={consoleRef}
                className="h-[300px] overflow-y-auto border-t border-zinc-900 pt-4 scrollbar-hide"
              >
                {scan.hits.map((hit, i) => (
                  <HitPanel key={i} hit={hit} />
                ))}
                {scan.hits.length === 0 && (
                  <div className="text-zinc-800 text-[0.6rem] text-center mt-10">
                    [ WAITING FOR HITS... ]
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
      
      {/* Absolute Bottom Info */}
      <div className="fixed bottom-4 left-4 right-4 flex justify-between items-center text-[0.5rem] text-zinc-700 pointer-events-none">
        <span>STRICTLY AUTHORIZED ASSETS ONLY</span>
        <span>RAVAN SEC CORE</span>
      </div>
    </div>
  );
}
