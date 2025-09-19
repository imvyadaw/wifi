#!/usr/bin/env python3
# wifi_monitor_treeview.py
# Passive Wi-Fi Monitor with fast Treeview and channel-utilization graph
# SAFE: No deauth / attack functionality.

import os, csv, time, tempfile, subprocess, threading, queue
from collections import deque, Counter
from tkinter import *
from tkinter import ttk
import matplotlib
matplotlib.use('Agg')  # avoid requiring X backend at import; we'll embed via FigureCanvasTkAgg if available
from matplotlib.figure import Figure

# ---------- Config ----------
SCAN_DURATION = 10       # seconds per airodump run (tune)
GUI_POLL_MS = 1000       # GUI poll interval in ms
CHANNEL_HISTORY = 30     # number of samples to keep for channel graph

# ---------- Scanner (passive) ----------
class PassiveScanner:
    def __init__(self, interface='wlan0', out_q=None):
        self.interface = interface
        self.out_q = out_q or queue.Queue(maxsize=5)
        self.stop_event = threading.Event()
        self.thread = None

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=1)

    def _run_airodump(self, duration):
        """Run airodump-ng for duration seconds, return list of csv rows or None on error."""
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                prefix = os.path.join(tmpdir, "scan")
                cmd = ["airodump-ng", self.interface, "-w", prefix, "--write-interval", "5", "-o", "csv"]
                proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    proc.wait(timeout=duration + 4)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except Exception:
                        proc.kill()
                csv_path = prefix + "-01.csv"
                rows = []
                if os.path.exists(csv_path):
                    with open(csv_path, newline='', encoding='utf-8', errors='ignore') as fh:
                        reader = csv.reader(fh)
                        for r in reader:
                            if r:
                                rows.append(r)
                return rows
        except FileNotFoundError:
            return None
        except Exception:
            return None

    @staticmethod
    def parse_rows(rows):
        if not rows:
            return [], []
        station_idx = None
        for idx, row in enumerate(rows):
            if row and row[0].strip() == "Station MAC":
                station_idx = idx
                break
        if station_idx is None:
            ap_rows = rows[1:]
            station_rows = []
        else:
            ap_rows = rows[1:station_idx]
            station_rows = rows[station_idx+1:]
        aps = []
        stations = []
        for r in ap_rows:
            if len(r) < 4:
                continue
            bssid = r[0].strip()
            channel = r[3].strip() if len(r) > 3 else ""
            ssid = r[13].strip() if len(r) > 13 else ""
            power = r[8].strip() if len(r) > 8 else ""
            if bssid and bssid != "BSSID":
                aps.append({'bssid':bssid,'channel':channel,'ssid':ssid,'power':power})
        for r in station_rows:
            if len(r) < 6:
                continue
            station_mac = r[0].strip()
            assoc = r[5].strip() if len(r) > 5 else ""
            power = r[3].strip() if len(r) > 3 else ""
            if station_mac and station_mac != "Station MAC":
                stations.append({'station':station_mac,'bssid':assoc,'power':power})
        return aps, stations

    def _loop(self):
        while not self.stop_event.is_set():
            rows = self._run_airodump(SCAN_DURATION)
            if rows is None:
                try:
                    self.out_q.put_nowait(("__ERROR__", "airodump-ng not available or interface issue"))
                except queue.Full:
                    pass
                time.sleep(2)
                continue
            aps, stations = self.parse_rows(rows)
            try:
                self.out_q.put((aps, stations), timeout=1)
            except queue.Full:
                try:
                    _ = self.out_q.get_nowait()
                    self.out_q.put_nowait((aps, stations))
                except Exception:
                    pass
            time.sleep(0.3)

# ---------- GUI with Treeview and Matplotlib graph ----------
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Fast WiFi Monitor (Treeview + Channel Graph)")
        self.q = queue.Queue()
        self.scanner = PassiveScanner(interface='wlan0', out_q=self.q)
        self.channel_history = deque(maxlen=CHANNEL_HISTORY)  # store Counters
        self._build_ui()
        self.root.after(GUI_POLL_MS, self._poll)

    def _build_ui(self):
        top = Frame(self.root)
        top.pack(fill=X, padx=4, pady=4)
        Label(top, text="Interface:").pack(side=LEFT)
        self.iface_var = StringVar(value='wlan0')
        Entry(top, textvariable=self.iface_var, width=10).pack(side=LEFT, padx=4)
        self.start_btn = Button(top, text="Start", command=self.start)
        self.start_btn.pack(side=LEFT, padx=4)
        self.stop_btn = Button(top, text="Stop", command=self.stop, state=DISABLED)
        self.stop_btn.pack(side=LEFT, padx=4)

        mid = PanedWindow(self.root, orient=HORIZONTAL)
        mid.pack(fill=BOTH, expand=True, padx=4, pady=4)

        # Left: Treeviews
        left = Frame(mid)
        mid.add(left, stretch='always')

        Label(left, text="Access Points").pack(anchor='w')
        self.ap_tree = ttk.Treeview(left, columns=('channel','ssid','power'), show='headings', height=20)
        self.ap_tree.heading('channel', text='Chan'); self.ap_tree.heading('ssid', text='SSID'); self.ap_tree.heading('power', text='Power')
        self.ap_tree.column('channel', width=60, anchor='center'); self.ap_tree.column('ssid', width=240); self.ap_tree.column('power', width=60, anchor='center')
        self.ap_tree.pack(fill=BOTH, expand=True)

        Label(left, text="Stations").pack(anchor='w')
        self.st_tree = ttk.Treeview(left, columns=('assoc','power'), show='headings', height=10)
        self.st_tree.heading('assoc', text='Associated BSSID'); self.st_tree.heading('power', text='Power')
        self.st_tree.column('assoc', width=200); self.st_tree.column('power', width=60, anchor='center')
        self.st_tree.pack(fill=BOTH, expand=True, pady=(4,0))

        # Right: Channel utilization graph (matplotlib)
        right = Frame(mid)
        mid.add(right, stretch='never')
        Label(right, text="Channel Utilization (AP count per channel)").pack()
        # Create a matplotlib Figure and embed into Tkinter if possible
        try:
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            self.fig = Figure(figsize=(5,3))
            self.ax = self.fig.add_subplot(111)
            self.canvas = FigureCanvasTkAgg(self.fig, master=right)
            self.canvas.get_tk_widget().pack(fill=BOTH, expand=True)
        except Exception:
            # If embedding not available, fallback to a text summary
            self.canvas = None
            self.ax = None
            self.txt_summary = Text(right, height=10)
            self.txt_summary.pack(fill=BOTH, expand=True)

    def start(self):
        iface = self.iface_var.get().strip()
        if not iface:
            return
        self.scanner.interface = iface
        self.scanner.start()
        self.start_btn.config(state=DISABLED); self.stop_btn.config(state=NORMAL)

    def stop(self):
        self.scanner.stop()
        self.start_btn.config(state=NORMAL); self.stop_btn.config(state=DISABLED)

    def _update_treeviews(self, aps, stations):
        # APs: keep Treeview small and fast by clearing and inserting (ok for moderate lists)
        self.ap_tree.delete(*self.ap_tree.get_children())
        for ap in aps:
            self.ap_tree.insert('', 'end', values=(ap['channel'], ap['ssid'][:40], ap['power'] ,), text=ap['bssid'])
        self.st_tree.delete(*self.st_tree.get_children())
        for st in stations:
            self.st_tree.insert('', 'end', values=(st['bssid'], st['power']), text=st['station'])

    def _update_channel_graph(self):
        if not self.channel_history:
            return
        # Build timeline for top channels across history
        # We'll show counts for channels 1..14 (2.4GHz) and aggregated for others
        counters = list(self.channel_history)
        # choose channels seen in most recent sample
        last = counters[-1]
        channels = sorted(set().union(*[c.keys() for c in counters]), key=lambda x: int(x) if x.isdigit() else 999)
        # prepare series
        series = {ch: [c.get(ch,0) for c in counters] for ch in channels}
        # plot
        if self.ax:
            self.ax.clear()
            for ch, vals in series.items():
                self.ax.plot(vals, label=ch)
            self.ax.set_ylabel("AP count")
            self.ax.set_xlabel("samples (new -> right)")
            self.ax.legend(loc='upper left', fontsize='small', ncol=2)
            self.fig.tight_layout()
            self.canvas.draw()
        else:
            # text fallback
            s = "Channel counts (latest):\n"
            s += ", ".join(f"{ch}:{counters[-1].get(ch,0)}" for ch in sorted(counters[-1].keys(), key=lambda x: int(x) if x.isdigit() else 999))
            self.txt_summary.delete('1.0', END)
            self.txt_summary.insert(END, s)

    def _poll(self):
        try:
            while True:
                item = self.q.get_nowait()
                if isinstance(item, tuple) and item[0] == "__ERROR__":
                    self.root.title(f"WiFi Monitor (Error) - {item[1]}")
                    continue
                aps, stations = item
                # Update treeviews
                self._update_treeviews(aps, stations)
                # update channel history
                ch_counts = Counter()
                for ap in aps:
                    ch = ap.get('channel','')
                    if ch == '':
                        continue
                    ch_counts[ch] += 1
                self.channel_history.append(ch_counts)
                self._update_channel_graph()
        except queue.Empty:
            pass
        finally:
            self.root.after(GUI_POLL_MS, self._poll)

def main():
    root = Tk()
    root.geometry('1100x700')
    app = App(root)
    # Connect scanner queue
    app.q = app.scanner.out_q
    root.protocol("WM_DELETE_WINDOW", lambda: (app.stop(), root.destroy()))
    root.mainloop()

if __name__ == "__main__":
    main()
