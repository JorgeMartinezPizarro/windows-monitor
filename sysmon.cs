// SysMon: monitor de sistema minimalista para Windows.
// Un único proceso: recolecta métricas 1 vez por segundo (PDH + NVML + Win32) y las sirve
// en http://localhost:<puerto>/ junto con index.html. Sin dependencias externas.
//
// Compilar (lo hace SysMon.bat automáticamente):
//   csc /nologo /optimize+ /out:sysmon.exe /r:System.Management.dll /r:System.Web.Extensions.dll sysmon.cs
// Uso:
//   sysmon.exe [puerto] [app|browser|none] [--lhm=8085] [--no-nvml]
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using Microsoft.Win32;

namespace SysMon
{
    static class Program
    {
        static volatile string snapshot = "{}";

        static int Main(string[] args)
        {
            int port = 8787;
            string mode = "app";
            bool useNvml = true;
            int lhmPort = 8085;
            foreach (string a in args)
            {
                int p;
                if (int.TryParse(a, out p)) port = p;
                else if (a == "--no-nvml") useNvml = false;
                else if (a.StartsWith("--lhm=")) int.TryParse(a.Substring(6), out lhmPort);
                else mode = a.ToLowerInvariant();
            }

            string url = "http://localhost:" + port + "/";
            string root = AppDomain.CurrentDomain.BaseDirectory;

            var listener = new HttpListener();
            listener.Prefixes.Add(url);
            try { listener.Start(); }
            catch (HttpListenerException)
            {
                Console.WriteLine("El puerto " + port + " ya esta en uso (SysMon ya abierto?). Abriendo " + url);
                OpenUi(url, mode);
                return 1;
            }

            var collector = new Collector(useNvml);
            var worker = new Thread(() => collector.Run(json => snapshot = json));
            worker.IsBackground = true;
            worker.Start();
            if (lhmPort > 0) Lhm.Start(lhmPort);

            Console.WriteLine("SysMon en " + url);
            Console.WriteLine("Cierra esta ventana (o Ctrl+C) para detenerlo.");
            OpenUi(url, mode);

            while (true)
            {
                HttpListenerContext ctx;
                try { ctx = listener.GetContext(); }
                catch { break; }
                ThreadPool.QueueUserWorkItem(o => Serve((HttpListenerContext)o, root), ctx);
            }
            return 0;
        }

        static void Serve(HttpListenerContext ctx, string root)
        {
            var res = ctx.Response;
            try
            {
                string path = ctx.Request.Url.AbsolutePath;
                byte[] body;
                if (path == "/api/stats")
                {
                    body = Encoding.UTF8.GetBytes(snapshot);
                    res.ContentType = "application/json";
                }
                else if (path == "/" || path == "/index.html")
                {
                    body = File.ReadAllBytes(Path.Combine(root, "index.html"));
                    res.ContentType = "text/html; charset=utf-8";
                }
                else
                {
                    res.StatusCode = 404;
                    body = new byte[0];
                }
                res.AddHeader("Cache-Control", "no-store");
                res.ContentLength64 = body.Length;
                res.OutputStream.Write(body, 0, body.Length);
            }
            catch { }
            finally { try { res.Close(); } catch { } }
        }

        static void OpenUi(string url, string mode)
        {
            if (mode == "none") return;
            if (mode == "app")
            {
                // Ventana de Edge sin pestañas ni barra de direcciones.
                try
                {
                    Process.Start(new ProcessStartInfo("msedge.exe", "--app=" + url + " --window-size=1280,860") { UseShellExecute = true });
                    return;
                }
                catch { }
            }
            try { Process.Start(url); } catch { }
        }
    }

    // ---------------------------------------------------------------- recolector

    class GpuInfo
    {
        public string Name = "GPU", Source = "";
        public double Usage = double.NaN, MemUsed = double.NaN, MemTotal = double.NaN, Temp = double.NaN,
                      Power = double.NaN, PowerLimit = double.NaN, Clock = double.NaN, MemClock = double.NaN, Fan = double.NaN;
    }

    class Collector
    {
        const int IntervalMs = 1000;
        static readonly Regex VirtualNic = new Regex("virtual|hyper-v|vmware|loopback|pseudo|miniport|kernel debug|tap-windows|wintun|wireguard|vpn|tailscale|zerotier", RegexOptions.IgnoreCase);
        static readonly Regex GpuLuid = new Regex(@"luid_(0x[0-9A-Fa-f]+_0x[0-9A-Fa-f]+)");
        static readonly Regex GpuEngType = new Regex(@"engtype_(.+)$");

        readonly bool useNvml;
        readonly Stopwatch clock = Stopwatch.StartNew();
        int tick;

        // PDH
        IntPtr query, cCpu, cCores, cPerf, cFreq, cProcs, cIdle, cRead, cWrite, cQueue, cTherm, cGpuEng, cGpuMem;
        bool thermTenths;
        readonly Dictionary<int, int> diskStall = new Dictionary<int, int>(); // muestras seguidas sin responder

        // NVML
        readonly List<IntPtr> nvDevices = new List<IntPtr>();
        readonly List<string> nvNames = new List<string>();

        // Estático (se lee una vez)
        string host, os, cpuName = "CPU", gpuFallbackName = "GPU";
        int cpuCores, cpuThreads = Environment.ProcessorCount;
        double vramFallbackTotal = double.NaN;
        readonly Dictionary<int, string> diskModels = new Dictionary<int, string>();

        // Red
        NetworkInterface[] nics = new NetworkInterface[0];
        readonly Dictionary<string, long[]> netPrev = new Dictionary<string, long[]>();
        double netPrevTime;

        // Volúmenes (se refrescan cada 5 s)
        string volsJson = "[]";

        public Collector(bool useNvml) { this.useNvml = useNvml; }

        public void Run(Action<string> publish)
        {
            Init();
            long next = clock.ElapsedMilliseconds + IntervalMs;
            while (true)
            {
                long wait = next - clock.ElapsedMilliseconds;
                if (wait > 0) Thread.Sleep((int)wait);
                next += IntervalMs;
                if (next < clock.ElapsedMilliseconds) next = clock.ElapsedMilliseconds + IntervalMs;
                try { publish(Sample()); }
                catch (Exception e) { Console.WriteLine("Error de muestreo: " + e.Message); }
            }
        }

        void Init()
        {
            host = Environment.MachineName;
            os = OsName();
            cpuName = Reg(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString", "CPU");
            cpuName = Regex.Replace(cpuName, @"\s+", " ").Trim();

            query = Pdh.Open();
            cCpu = Pdh.Add(query, @"\Processor Information(_Total)\% Processor Utility");
            cCores = Pdh.Add(query, @"\Processor Information(*)\% Processor Utility");
            if (cCpu == IntPtr.Zero)
            {
                cCpu = Pdh.Add(query, @"\Processor(_Total)\% Processor Time");
                cCores = Pdh.Add(query, @"\Processor(*)\% Processor Time");
            }
            cPerf = Pdh.Add(query, @"\Processor Information(_Total)\% Processor Performance");
            cFreq = Pdh.Add(query, @"\Processor Information(_Total)\Processor Frequency");
            cProcs = Pdh.Add(query, @"\System\Processes");
            cIdle = Pdh.Add(query, @"\PhysicalDisk(*)\% Idle Time");
            cRead = Pdh.Add(query, @"\PhysicalDisk(*)\Disk Read Bytes/sec");
            cWrite = Pdh.Add(query, @"\PhysicalDisk(*)\Disk Write Bytes/sec");
            cQueue = Pdh.Add(query, @"\PhysicalDisk(*)\Current Disk Queue Length");
            cTherm = Pdh.Add(query, @"\Thermal Zone Information(*)\High Precision Temperature");
            thermTenths = cTherm != IntPtr.Zero;
            if (!thermTenths) cTherm = Pdh.Add(query, @"\Thermal Zone Information(*)\Temperature");

            if (useNvml) InitNvml();
            if (nvDevices.Count == 0)
            {
                // Sin NVIDIA: contadores genéricos de Windows (como el Administrador de tareas).
                cGpuEng = Pdh.Add(query, @"\GPU Engine(*)\Utilization Percentage");
                cGpuMem = Pdh.Add(query, @"\GPU Adapter Memory(*)\Dedicated Usage");
                vramFallbackTotal = RegistryVram();
            }

            ReadWmi();
            Pdh.Collect(query);
            RefreshNics();
            SampleNet();
            volsJson = Volumes();

            Console.WriteLine("CPU: " + cpuName);
            Console.WriteLine("GPU: " + (nvDevices.Count > 0 ? "NVML (" + string.Join(", ", nvNames) + ")" : "contadores de Windows (" + gpuFallbackName + ")"));
        }

        void InitNvml()
        {
            try
            {
                if (Nvml.Init() != 0) return;
                uint count;
                if (Nvml.GetCount(out count) != 0) return;
                for (uint i = 0; i < count; i++)
                {
                    IntPtr dev;
                    if (Nvml.GetHandle(i, out dev) != 0) continue;
                    var sb = new StringBuilder(96);
                    nvDevices.Add(dev);
                    nvNames.Add(Nvml.GetName(dev, sb, (uint)sb.Capacity) == 0 ? sb.ToString() : "NVIDIA GPU");
                }
            }
            catch (DllNotFoundException) { }
            catch (EntryPointNotFoundException) { }
        }

        void ReadWmi()
        {
            try
            {
                using (var s = new ManagementObjectSearcher("SELECT Index, Model FROM Win32_DiskDrive"))
                    foreach (ManagementObject o in s.Get())
                        diskModels[Convert.ToInt32(o["Index"])] = Convert.ToString(o["Model"]).Trim();
            }
            catch { }
            try
            {
                using (var s = new ManagementObjectSearcher("SELECT NumberOfCores FROM Win32_Processor"))
                    foreach (ManagementObject o in s.Get())
                        cpuCores += Convert.ToInt32(o["NumberOfCores"]);
            }
            catch { }
            if (nvDevices.Count > 0) return;
            try
            {
                using (var s = new ManagementObjectSearcher("SELECT Name FROM Win32_VideoController"))
                    foreach (ManagementObject o in s.Get())
                    {
                        string n = Convert.ToString(o["Name"]);
                        if (n.IndexOf("Basic", StringComparison.OrdinalIgnoreCase) < 0) { gpuFallbackName = n; break; }
                    }
            }
            catch { }
        }

        string Sample()
        {
            tick++;
            Pdh.Collect(query);
            var j = new StringBuilder(4096);
            LhmTemp[] lhm = Lhm.Temps;
            LhmTemp cpuTemp = lhm.FirstOrDefault(x => x.Kind == "cpu");

            // --- CPU
            double cpu = Clamp(Pdh.Get(cCpu));
            double perf = Pdh.Get(cPerf), freq = Pdh.Get(cFreq);
            double mhz = (double.IsNaN(perf) || double.IsNaN(freq)) ? double.NaN : freq * perf / 100.0;
            var cores = new List<KeyValuePair<long, double>>();
            foreach (var kv in Pdh.GetAll(cCores))
            {
                if (kv.Key.Contains("_Total")) continue;
                string[] parts = kv.Key.Split(',');
                long g = 0, idx;
                if (parts.Length == 2) long.TryParse(parts[0], out g);
                if (!long.TryParse(parts[parts.Length - 1], out idx)) continue;
                cores.Add(new KeyValuePair<long, double>(g * 4096 + idx, Clamp(kv.Value)));
            }
            cores.Sort((a, b) => a.Key.CompareTo(b.Key));

            j.Append("{\"t\":").Append(N((DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalMilliseconds));
            j.Append(",\"host\":").Append(S(host)).Append(",\"os\":").Append(S(os));
            j.Append(",\"uptime\":").Append(N(GetTickCount64() / 1000.0));
            j.Append(",\"cpu\":{\"name\":").Append(S(cpuName))
             .Append(",\"cores\":").Append(cpuCores).Append(",\"threads\":").Append(cpuThreads)
             .Append(",\"usage\":").Append(N(cpu)).Append(",\"mhz\":").Append(N(mhz))
             .Append(",\"temp\":").Append(N(cpuTemp == null ? double.NaN : cpuTemp.C))
             .Append(",\"procs\":").Append(N(Pdh.Get(cProcs)))
             .Append(",\"per\":[").Append(string.Join(",", cores.Select(c => N(c.Value)))).Append("]}");

            // --- RAM
            var m = new MEMORYSTATUSEX();
            GlobalMemoryStatusEx(m);
            j.Append(",\"ram\":{\"total\":").Append(N(m.ullTotalPhys))
             .Append(",\"used\":").Append(N(m.ullTotalPhys - m.ullAvailPhys))
             .Append(",\"avail\":").Append(N(m.ullAvailPhys))
             .Append(",\"commit\":").Append(N(m.ullTotalPageFile - m.ullAvailPageFile))
             .Append(",\"commitLimit\":").Append(N(m.ullTotalPageFile)).Append("}");

            // --- GPU / VRAM
            List<GpuInfo> gpus = nvDevices.Count > 0 ? SampleNvml() : SampleGpuPdh();
            j.Append(",\"gpus\":[").Append(string.Join(",", gpus.Select(g =>
                "{\"name\":" + S(g.Name) + ",\"src\":" + S(g.Source) +
                ",\"usage\":" + N(g.Usage) + ",\"memUsed\":" + N(g.MemUsed) + ",\"memTotal\":" + N(g.MemTotal) +
                ",\"temp\":" + N(g.Temp) + ",\"power\":" + N(g.Power) + ",\"powerLimit\":" + N(g.PowerLimit) +
                ",\"clock\":" + N(g.Clock) + ",\"memClock\":" + N(g.MemClock) + ",\"fan\":" + N(g.Fan) + "}"))).Append("]");

            // --- Disco
            var idle = Pdh.GetAll(cIdle);
            var rd = Pdh.GetAll(cRead);
            var wr = Pdh.GetAll(cWrite);
            var qd = Pdh.GetAll(cQueue);
            var disks = new List<KeyValuePair<int, string>>();
            foreach (var kv in idle)
            {
                if (kv.Key == "_Total") continue;
                string[] parts = kv.Key.Split(' ');
                int id;
                if (!int.TryParse(parts[0], out id)) continue;
                string model;
                diskModels.TryGetValue(id, out model);
                double r, w, q;
                rd.TryGetValue(kv.Key, out r);
                wr.TryGetValue(kv.Key, out w);
                if (!qd.TryGetValue(kv.Key, out q)) q = double.NaN;
                double active = Clamp(100 - kv.Value);
                // Windows cuenta los bytes al terminar cada petición. Si hay peticiones en cola y en todo el
                // segundo no termina ninguna, el disco no responde: sale ~100 % activo con 0 B/s.
                int stall;
                diskStall.TryGetValue(id, out stall);
                diskStall[id] = stall = (q >= 1 && r < 1 && w < 1 && active >= 95) ? stall + 1 : 0;
                disks.Add(new KeyValuePair<int, string>(id,
                    "{\"id\":" + id + ",\"model\":" + S(model ?? ("Disco " + id)) +
                    ",\"letters\":" + S(string.Join(" ", parts.Skip(1))) +
                    ",\"active\":" + N(active) + ",\"read\":" + N(r) + ",\"write\":" + N(w) +
                    ",\"queue\":" + N(q) + ",\"stall\":" + N(stall * IntervalMs / 1000.0) + "}"));
            }
            disks.Sort((a, b) => a.Key.CompareTo(b.Key));
            if (tick % 5 == 0) volsJson = Volumes();
            j.Append(",\"disks\":[").Append(string.Join(",", disks.Select(d => d.Value))).Append("]");
            j.Append(",\"vols\":").Append(volsJson);

            // --- Red
            if (tick % 10 == 0) RefreshNics();
            j.Append(",\"net\":").Append(SampleNet());

            // --- Temperaturas: CPU y discos (LibreHardwareMonitor), GPU (NVML) y zonas ACPI (Windows)
            var temps = new List<string>();
            Func<string, string, double, string> temp = (name, kind, c) =>
                "{\"name\":" + S(name) + ",\"kind\":\"" + kind + "\",\"c\":" + N(c) + "}";
            foreach (var t in lhm.Where(x => x.Kind == "cpu")) temps.Add(temp(t.Name, "cpu", t.C));
            foreach (var g in gpus)
                if (!double.IsNaN(g.Temp)) temps.Add(temp(g.Name, "gpu", g.Temp));
            foreach (var t in lhm.Where(x => x.Kind == "disk")) temps.Add(temp(t.Name, "disk", t.C));
            foreach (var kv in Pdh.GetAll(cTherm).OrderBy(k => k.Key))
            {
                double c = thermTenths ? kv.Value / 10.0 - 273.15 : kv.Value - 273.15;
                if (c < -40 || c > 150) continue;
                temps.Add(temp("Zona ACPI " + kv.Key.Substring(kv.Key.LastIndexOf('.') + 1), "acpi", c));
            }
            j.Append(",\"temps\":[").Append(string.Join(",", temps)).Append("]");
            j.Append(",\"lhm\":").Append(Lhm.Online ? "true" : "false").Append("}");
            return j.ToString();
        }

        List<GpuInfo> SampleNvml()
        {
            var list = new List<GpuInfo>();
            for (int i = 0; i < nvDevices.Count; i++)
            {
                IntPtr d = nvDevices[i];
                var g = new GpuInfo { Name = nvNames[i], Source = "nvml" };
                Nvml.Util u;
                Nvml.Mem mem;
                uint v;
                if (Nvml.GetUtil(d, out u) == 0) g.Usage = u.Gpu;
                if (Nvml.GetMem(d, out mem) == 0) { g.MemUsed = mem.Used; g.MemTotal = mem.Total; }
                if (Nvml.GetTemp(d, 0, out v) == 0) g.Temp = v;
                if (Nvml.GetPower(d, out v) == 0) g.Power = v / 1000.0;
                if (Nvml.GetPowerLimit(d, out v) == 0) g.PowerLimit = v / 1000.0;
                if (Nvml.GetClock(d, 0, out v) == 0) g.Clock = v;
                if (Nvml.GetClock(d, 2, out v) == 0) g.MemClock = v;
                if (Nvml.GetFan(d, out v) == 0) g.Fan = v;
                list.Add(g);
            }
            return list;
        }

        // Igual que el Administrador de tareas: por adaptador, suma por tipo de motor y se toma el máximo.
        List<GpuInfo> SampleGpuPdh()
        {
            var list = new List<GpuInfo>();
            if (cGpuEng == IntPtr.Zero && cGpuMem == IntPtr.Zero) return list;

            var byEngine = new Dictionary<string, double>();
            foreach (var kv in Pdh.GetAll(cGpuEng))
            {
                Match l = GpuLuid.Match(kv.Key), e = GpuEngType.Match(kv.Key);
                if (!l.Success || !e.Success) continue;
                string key = l.Groups[1].Value + "|" + e.Groups[1].Value;
                double s;
                byEngine.TryGetValue(key, out s);
                byEngine[key] = s + kv.Value;
            }
            var byAdapter = new Dictionary<string, double>();
            foreach (var kv in byEngine)
            {
                string luid = kv.Key.Split('|')[0];
                double s;
                byAdapter.TryGetValue(luid, out s);
                byAdapter[luid] = Math.Max(s, kv.Value);
            }

            // El adaptador con más memoria dedicada en uso es la GPU principal.
            string best = null;
            double bestMem = -1;
            foreach (var kv in Pdh.GetAll(cGpuMem))
            {
                Match l = GpuLuid.Match(kv.Key);
                if (l.Success && kv.Value > bestMem) { bestMem = kv.Value; best = l.Groups[1].Value; }
            }
            if (best == null) best = byAdapter.Keys.FirstOrDefault();
            if (best == null) return list;

            double usage;
            byAdapter.TryGetValue(best, out usage);
            list.Add(new GpuInfo
            {
                Name = gpuFallbackName, Source = "pdh", Usage = Clamp(usage),
                MemUsed = bestMem >= 0 ? bestMem : double.NaN, MemTotal = vramFallbackTotal
            });
            return list;
        }

        void RefreshNics()
        {
            try
            {
                nics = NetworkInterface.GetAllNetworkInterfaces().Where(n =>
                    n.OperationalStatus == OperationalStatus.Up &&
                    n.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                    n.NetworkInterfaceType != NetworkInterfaceType.Tunnel).ToArray();
            }
            catch { }
        }

        string SampleNet()
        {
            double now = clock.Elapsed.TotalSeconds, dt = now - netPrevTime;
            netPrevTime = now;
            double rxPhys = 0, txPhys = 0, rxAll = 0, txAll = 0;
            bool anyPhys = false;
            var rows = new List<KeyValuePair<string, string>>();
            foreach (var n in nics)
            {
                long rx, tx;
                try
                {
                    var st = n.GetIPStatistics();
                    rx = st.BytesReceived;
                    tx = st.BytesSent;
                }
                catch { continue; }

                double rxRate = double.NaN, txRate = double.NaN;
                long[] prev;
                if (netPrev.TryGetValue(n.Id, out prev) && dt > 0)
                {
                    rxRate = Math.Max(0, rx - prev[0]) / dt;
                    txRate = Math.Max(0, tx - prev[1]) / dt;
                }
                netPrev[n.Id] = new[] { rx, tx };

                bool virt = VirtualNic.IsMatch(n.Name + " " + n.Description);
                if (!double.IsNaN(rxRate))
                {
                    rxAll += rxRate; txAll += txRate;
                    if (!virt) { rxPhys += rxRate; txPhys += txRate; }
                }
                if (!virt) anyPhys = true;
                rows.Add(new KeyValuePair<string, string>((virt ? "1" : "0") + n.Name,
                    "{\"name\":" + S(n.Name) + ",\"desc\":" + S(n.Description) +
                    ",\"rx\":" + N(rxRate) + ",\"tx\":" + N(txRate) + ",\"speed\":" + N(n.Speed) +
                    ",\"virtual\":" + (virt ? "true" : "false") + "}"));
            }
            rows.Sort((a, b) => string.CompareOrdinal(a.Key, b.Key));
            return "{\"rx\":" + N(anyPhys ? rxPhys : rxAll) + ",\"tx\":" + N(anyPhys ? txPhys : txAll) +
                   ",\"adapters\":[" + string.Join(",", rows.Select(r => r.Value)) + "]}";
        }

        static string Volumes()
        {
            var parts = new List<string>();
            foreach (var d in DriveInfo.GetDrives())
            {
                try
                {
                    if (d.DriveType != DriveType.Fixed || !d.IsReady) continue;
                    parts.Add("{\"name\":" + S(d.Name.TrimEnd('\\')) + ",\"label\":" + S(d.VolumeLabel) +
                              ",\"total\":" + N(d.TotalSize) + ",\"free\":" + N(d.TotalFreeSpace) + "}");
                }
                catch { }
            }
            return "[" + string.Join(",", parts) + "]";
        }

        static double RegistryVram()
        {
            double best = double.NaN;
            try
            {
                using (var cls = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"))
                {
                    if (cls == null) return best;
                    foreach (string sub in cls.GetSubKeyNames())
                    {
                        if (sub.Length != 4) continue;
                        try
                        {
                            using (var k = cls.OpenSubKey(sub))
                            {
                                object v = k == null ? null : k.GetValue("HardwareInformation.qwMemorySize");
                                if (v == null) continue;
                                double size = Convert.ToDouble(v);
                                if (double.IsNaN(best) || size > best) best = size;
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
            return best;
        }

        static string OsName()
        {
            string name = Reg(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName", "Windows");
            int build;
            int.TryParse(Reg(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild", "0"), out build);
            if (build >= 22000) name = name.Replace("Windows 10", "Windows 11");
            return (name + " " + Reg(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion", "")).Trim();
        }

        static string Reg(string key, string value, string fallback)
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(key))
                {
                    object v = k == null ? null : k.GetValue(value);
                    return v == null ? fallback : v.ToString();
                }
            }
            catch { return fallback; }
        }

        static double Clamp(double v) { return double.IsNaN(v) ? v : Math.Max(0, Math.Min(100, v)); }

        static string N(double v)
        {
            if (double.IsNaN(v) || double.IsInfinity(v)) return "null";
            return Math.Round(v, 2).ToString(CultureInfo.InvariantCulture);
        }

        static string S(string s)
        {
            if (s == null) return "null";
            var sb = new StringBuilder(s.Length + 2);
            sb.Append('"');
            foreach (char c in s)
            {
                if (c == '"' || c == '\\') sb.Append('\\').Append(c);
                else if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                else sb.Append(c);
            }
            return sb.Append('"').ToString();
        }

        [StructLayout(LayoutKind.Sequential)]
        class MEMORYSTATUSEX
        {
            public uint dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
            public uint dwMemoryLoad;
            public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile, ullAvailPageFile, ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual;
        }

        [DllImport("kernel32.dll")]
        static extern bool GlobalMemoryStatusEx([In, Out] MEMORYSTATUSEX m);

        [DllImport("kernel32.dll")]
        static extern ulong GetTickCount64();
    }

    // ---------------------------------------------------------------- PDH (contadores de rendimiento)
    // PdhAddEnglishCounter acepta nombres en inglés con cualquier idioma de Windows.

    static class Pdh
    {
        const uint FMT = 0x200 | 0x8000; // PDH_FMT_DOUBLE | PDH_FMT_NOCAP100
        const uint MORE_DATA = 0x800007D2;

        [StructLayout(LayoutKind.Sequential)] struct Value { public uint Status; public double Double; }
        [StructLayout(LayoutKind.Sequential)] struct Item { public IntPtr Name; public Value Value; }

        [DllImport("pdh.dll", CharSet = CharSet.Unicode)] static extern uint PdhOpenQuery(string source, IntPtr user, out IntPtr query);
        [DllImport("pdh.dll", CharSet = CharSet.Unicode)] static extern uint PdhAddEnglishCounter(IntPtr query, string path, IntPtr user, out IntPtr counter);
        [DllImport("pdh.dll")] static extern uint PdhCollectQueryData(IntPtr query);
        [DllImport("pdh.dll")] static extern uint PdhGetFormattedCounterValue(IntPtr counter, uint format, out uint type, out Value value);
        [DllImport("pdh.dll", CharSet = CharSet.Unicode)] static extern uint PdhGetFormattedCounterArray(IntPtr counter, uint format, ref uint size, out uint count, IntPtr buffer);

        public static IntPtr Open()
        {
            IntPtr q;
            return PdhOpenQuery(null, IntPtr.Zero, out q) == 0 ? q : IntPtr.Zero;
        }

        public static IntPtr Add(IntPtr query, string path)
        {
            IntPtr c;
            return query != IntPtr.Zero && PdhAddEnglishCounter(query, path, IntPtr.Zero, out c) == 0 ? c : IntPtr.Zero;
        }

        public static void Collect(IntPtr query) { if (query != IntPtr.Zero) PdhCollectQueryData(query); }

        public static double Get(IntPtr counter)
        {
            if (counter == IntPtr.Zero) return double.NaN;
            uint type;
            Value v;
            if (PdhGetFormattedCounterValue(counter, FMT, out type, out v) != 0 || v.Status > 1) return double.NaN;
            return v.Double;
        }

        public static Dictionary<string, double> GetAll(IntPtr counter)
        {
            var res = new Dictionary<string, double>();
            if (counter == IntPtr.Zero) return res;
            for (int attempt = 0; attempt < 3; attempt++)
            {
                uint size = 0, count;
                if (PdhGetFormattedCounterArray(counter, FMT, ref size, out count, IntPtr.Zero) != MORE_DATA || size == 0) return res;
                IntPtr buf = Marshal.AllocHGlobal((int)size);
                try
                {
                    uint st = PdhGetFormattedCounterArray(counter, FMT, ref size, out count, buf);
                    if (st == MORE_DATA) continue; // aparecieron instancias nuevas entre llamadas
                    if (st != 0) return res;
                    int stride = Marshal.SizeOf(typeof(Item));
                    for (int i = 0; i < count; i++)
                    {
                        var it = (Item)Marshal.PtrToStructure(new IntPtr(buf.ToInt64() + (long)i * stride), typeof(Item));
                        if (it.Value.Status > 1) continue;
                        res[Marshal.PtrToStringUni(it.Name)] = it.Value.Double;
                    }
                    return res;
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            return res;
        }
    }

    // ---------------------------------------------------------------- LibreHardwareMonitor (opcional)
    // Windows no expone la temperatura de la CPU sin un driver de kernel. Si LibreHardwareMonitor está abierto
    // (como administrador) con "Options > Remote Web Server" activo, se leen sus sensores de /data.json.

    class LhmTemp { public string Name, Kind; public double C; }

    static class Lhm
    {
        class Raw { public string HwId, HwName, Kind, Name; public double C; }

        // Sensor principal de la CPU, por orden de preferencia (Intel y AMD).
        static readonly string[] CpuMain = { "CPU Package", "Package", "Core (Tctl/Tdie)", "Tctl/Tdie", "Tdie", "Tctl", "Core Max" };
        static readonly Regex DiskId = new Regex(@"^/(nvme|hdd|ssd|ata|scsi|storage)", RegexOptions.IgnoreCase);
        static readonly Regex NotATemp = new Regex("distance|tjmax|warning|critical|limit", RegexOptions.IgnoreCase);
        static readonly Regex Number = new Regex(@"-?\d+(?:[.,]\d+)?");

        public static volatile bool Online;
        public static volatile LhmTemp[] Temps = new LhmTemp[0];

        public static void Start(int port)
        {
            // 127.0.0.1 y no "localhost": evita el intento previo por IPv6 y vale tanto si LHM escucha en todas las IP como solo en loopback.
            string url = "http://127.0.0.1:" + port + "/data.json";
            Console.WriteLine("LibreHardwareMonitor: buscando en " + url);
            var t = new Thread(() => Loop(url)) { IsBackground = true, Priority = ThreadPriority.BelowNormal };
            t.Start();
        }

        static void Loop(string url)
        {
            var json = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
            while (true)
            {
                bool was = Online;
                try
                {
                    var req = (HttpWebRequest)WebRequest.Create(url);
                    req.Proxy = null;
                    req.Timeout = req.ReadWriteTimeout = 1500;
                    string body;
                    using (var res = req.GetResponse())
                    using (var sr = new StreamReader(res.GetResponseStream(), Encoding.UTF8))
                        body = sr.ReadToEnd();
                    Temps = Parse(json.DeserializeObject(body));
                    Online = true;
                }
                catch
                {
                    Online = false;
                    Temps = new LhmTemp[0];
                }
                if (Online != was) Console.WriteLine(Online ? "LibreHardwareMonitor: conectado" : "LibreHardwareMonitor: desconectado");
                Thread.Sleep(Online ? 2000 : 5000);
            }
        }

        static LhmTemp[] Parse(object root)
        {
            var raw = new List<Raw>();
            Walk(root as Dictionary<string, object>, null, null, raw);

            var result = new List<LhmTemp>();
            var cpuIds = raw.Where(r => r.Kind == "cpu").Select(r => r.HwId).Distinct().ToList();
            foreach (string id in cpuIds)
            {
                var sensors = raw.Where(r => r.HwId == id).ToList();
                string suffix = cpuIds.Count > 1 ? " #" + (cpuIds.IndexOf(id) + 1) : "";
                Raw main = null;
                foreach (string name in CpuMain)
                    if ((main = sensors.FirstOrDefault(r => r.Name == name)) != null) break;
                if (main == null) main = sensors.OrderByDescending(r => r.C).First();
                result.Add(new LhmTemp { Name = main.Name + suffix, Kind = "cpu", C = main.C });
                Raw hottest = sensors.FirstOrDefault(r => r.Name == "Core Max");
                if (hottest != null && hottest != main) result.Add(new LhmTemp { Name = "Núcleo más caliente" + suffix, Kind = "cpu", C = hottest.C });
            }
            foreach (var disk in raw.Where(r => r.Kind == "disk").GroupBy(r => r.HwId))
            {
                Raw t = disk.FirstOrDefault(r => r.Name == "Temperature") ?? disk.First();
                result.Add(new LhmTemp { Name = t.HwName, Kind = "disk", C = t.C });
            }
            return result.ToArray();
        }

        // Árbol: equipo > hardware (HardwareId) > grupo por tipo ("Temperatures") > sensor (SensorId, Type, RawValue).
        // Las versiones antiguas no tienen HardwareId/Type: se deduce por el icono y el nombre del grupo.
        static void Walk(Dictionary<string, object> n, Raw hw, string group, List<Raw> acc)
        {
            if (n == null) return;
            string text = Str(n, "Text") ?? "", image = Str(n, "ImageURL") ?? "", hwId = Str(n, "HardwareId");
            string kind = null;
            if (hwId != null) kind = hwId.StartsWith("/intelcpu") || hwId.StartsWith("/amdcpu") ? "cpu" : DiskId.IsMatch(hwId) ? "disk" : "other";
            else if (image.EndsWith("/cpu.png")) kind = "cpu";
            else if (image.EndsWith("/hdd.png")) kind = "disk";
            if (kind != null) { hw = new Raw { HwId = hwId ?? text, HwName = text, Kind = kind }; group = null; }

            var kids = Kids(n);
            if (hw != null && kind == null && (n.ContainsKey("SensorId") || (kids.Count == 0 && group != null)))
            {
                string type = Str(n, "Type");
                bool isTemp = type != null ? type == "Temperature" : group == "Temperatures";
                if (isTemp && hw.Kind != "other" && !NotATemp.IsMatch(text))
                {
                    double c = Celsius(n);
                    if (c > 0 && c < 150) acc.Add(new Raw { HwId = hw.HwId, HwName = hw.HwName, Kind = hw.Kind, Name = text, C = c });
                }
                return;
            }
            if (hw != null && kind == null) group = text;
            foreach (object k in kids) Walk(k as Dictionary<string, object>, hw, group, acc);
        }

        static double Celsius(Dictionary<string, object> n)
        {
            object raw;
            if (n.TryGetValue("RawValue", out raw) && raw != null)
            {
                try { return Convert.ToDouble(raw, CultureInfo.InvariantCulture); } catch { }
            }
            // Versiones antiguas: solo texto con formato local, p. ej. "45,0 °C" o "113.0 °F".
            string s = Str(n, "Value");
            Match m = s == null ? null : Number.Match(s);
            if (m == null || !m.Success) return double.NaN;
            double v = double.Parse(m.Value.Replace(',', '.'), CultureInfo.InvariantCulture);
            return s.Contains("°F") ? (v - 32) / 1.8 : v;
        }

        static string Str(Dictionary<string, object> n, string key)
        {
            object v;
            return n.TryGetValue(key, out v) && v != null ? v.ToString() : null;
        }

        static List<object> Kids(Dictionary<string, object> n)
        {
            object v;
            var list = new List<object>();
            var e = n.TryGetValue("Children", out v) ? v as IEnumerable : null;
            if (e != null && !(v is string)) foreach (object o in e) list.Add(o);
            return list;
        }
    }

    // ---------------------------------------------------------------- NVML (driver de NVIDIA, en System32)

    static class Nvml
    {
        const string Dll = "nvml.dll";
        const CallingConvention Cc = CallingConvention.Cdecl;

        [StructLayout(LayoutKind.Sequential)] public struct Util { public uint Gpu, Memory; }
        [StructLayout(LayoutKind.Sequential)] public struct Mem { public ulong Total, Free, Used; }

        [DllImport(Dll, CallingConvention = Cc, EntryPoint = "nvmlInit_v2")] public static extern int Init();
        [DllImport(Dll, CallingConvention = Cc, EntryPoint = "nvmlDeviceGetCount_v2")] public static extern int GetCount(out uint count);
        [DllImport(Dll, CallingConvention = Cc, EntryPoint = "nvmlDeviceGetHandleByIndex_v2")] public static extern int GetHandle(uint index, out IntPtr device);
        [DllImport(Dll, CallingConvention = Cc, EntryPoint = "nvmlDeviceGetName", CharSet = CharSet.Ansi)] public static extern int GetName(IntPtr device, StringBuilder name, uint length);
        [DllImport(Dll, CallingConvention = Cc, EntryPoint = "nvmlDeviceGetUtilizationRates")] public static extern int GetUtil(IntPtr device, out Util util);
        [DllImport(Dll, CallingConvention = Cc, EntryPoint = "nvmlDeviceGetMemoryInfo")] public static extern int GetMem(IntPtr device, out Mem mem);
        [DllImport(Dll, CallingConvention = Cc, EntryPoint = "nvmlDeviceGetTemperature")] public static extern int GetTemp(IntPtr device, int sensor, out uint celsius);
        [DllImport(Dll, CallingConvention = Cc, EntryPoint = "nvmlDeviceGetPowerUsage")] public static extern int GetPower(IntPtr device, out uint milliwatts);
        [DllImport(Dll, CallingConvention = Cc, EntryPoint = "nvmlDeviceGetEnforcedPowerLimit")] public static extern int GetPowerLimit(IntPtr device, out uint milliwatts);
        [DllImport(Dll, CallingConvention = Cc, EntryPoint = "nvmlDeviceGetClockInfo")] public static extern int GetClock(IntPtr device, int type, out uint mhz);
        [DllImport(Dll, CallingConvention = Cc, EntryPoint = "nvmlDeviceGetFanSpeed")] public static extern int GetFan(IntPtr device, out uint percent);
    }
}
