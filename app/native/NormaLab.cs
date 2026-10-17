// NORMA lab: packet-level experiments on top of WinDivert (x64).
// Intercepts ONLY outbound TCP:443 packets to one chosen IP while a test is running,
// everything else in the system is untouched. Written for C# 5 (Windows PowerShell 5.1 Add-Type).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace Norma
{
    public class Strategy
    {
        public string Name;
        public int FakeRepeats;     // 0 = no fake packets
        public int FakeTtl;         // >0: fake packet with a low TTL (dies before the server)
        public bool FakeBadSeq;     // fake packet with an out-of-window sequence number
        public bool FakeMd5;        // fake packet carrying a TCP MD5-signature option (Linux servers drop it)
        public bool FakeBadSum;     // fake packet with a wrong TCP checksum
        public string Split;        // "none" | "split" | "disorder"
        public int SplitPos;        // >0 absolute offset; -1 middle of host name; -2 start of host name
        public string FakeSni;
    }

    public class TestResult
    {
        public bool Ok;
        public int Ms;
        public string Stage;
        public string Error;
    }

    internal static class Native
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr LoadLibrary(string path);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        public static extern bool WinDivertRecv(IntPtr handle, byte[] packet, uint packetLen, out uint recvLen, byte[] addr);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        public static extern bool WinDivertSend(IntPtr handle, byte[] packet, uint packetLen, out uint sendLen, byte[] addr);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        public static extern bool WinDivertClose(IntPtr handle);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        public static extern bool WinDivertHelperCalcChecksums(byte[] packet, uint packetLen, byte[] addr, ulong flags);
    }

    // Fake / reference TLS ClientHello builder
    internal static class Hello
    {
        private static void U16(List<byte> l, int v)
        {
            l.Add((byte)(v >> 8));
            l.Add((byte)v);
        }

        public static byte[] Build(string sni)
        {
            return Build(sni, 0, false);
        }

        // padTo > 0: pad the record to about this many bytes (a large hello is sent in several TCP packets).
        // sniLast: put the server_name extension at the very end (so it lands in the second packet).
        public static byte[] Build(string sni, int padTo, bool sniLast)
        {
            byte[] random = new byte[32];
            byte[] session = new byte[32];
            byte[] share = new byte[32];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(random);
                rng.GetBytes(session);
                rng.GetBytes(share);
            }
            byte[] name = Encoding.ASCII.GetBytes(sni);

            List<byte> pre = new List<byte>();
            U16(pre, 0x0303);
            pre.AddRange(random);
            pre.Add(32);
            pre.AddRange(session);
            int[] suites = { 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035 };
            U16(pre, suites.Length * 2);
            foreach (int s in suites) { U16(pre, s); }
            pre.Add(1);
            pre.Add(0);

            List<byte> sniExt = new List<byte>();
            U16(sniExt, 0x0000); U16(sniExt, name.Length + 5); U16(sniExt, name.Length + 3);
            sniExt.Add(0); U16(sniExt, name.Length); sniExt.AddRange(name);

            List<byte> oth = new List<byte>();
            U16(oth, 0x000A); U16(oth, 6); U16(oth, 4); U16(oth, 0x001D); U16(oth, 0x0017);
            U16(oth, 0x000B); U16(oth, 2); oth.Add(1); oth.Add(0);
            int[] sig = { 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601 };
            U16(oth, 0x000D); U16(oth, 2 + sig.Length * 2); U16(oth, sig.Length * 2);
            foreach (int s in sig) { U16(oth, s); }
            U16(oth, 0x0010); U16(oth, 14); U16(oth, 12);
            oth.Add(2); oth.Add(0x68); oth.Add(0x32);
            oth.Add(8); oth.AddRange(Encoding.ASCII.GetBytes("http/1.1"));
            U16(oth, 0x002B); U16(oth, 5); oth.Add(4); U16(oth, 0x0304); U16(oth, 0x0303);
            U16(oth, 0x0033); U16(oth, 38); U16(oth, 36); U16(oth, 0x001D); U16(oth, 32); oth.AddRange(share);
            U16(oth, 0x002D); U16(oth, 2); oth.Add(1); oth.Add(1);

            List<byte> padExt = new List<byte>();
            int baseLen = 5 + 4 + pre.Count + 2 + sniExt.Count + oth.Count;
            if (padTo > baseLen + 4)
            {
                int pl = padTo - baseLen - 4;
                U16(padExt, 0x0015);
                U16(padExt, pl);
                for (int i = 0; i < pl; i++) padExt.Add(0);
            }

            List<byte> ext = new List<byte>();
            if (sniLast) { ext.AddRange(oth); ext.AddRange(padExt); ext.AddRange(sniExt); }
            else { ext.AddRange(sniExt); ext.AddRange(oth); ext.AddRange(padExt); }

            int bodyLen = pre.Count + 2 + ext.Count;
            List<byte> hs = new List<byte>();
            hs.Add(1);
            hs.Add((byte)(bodyLen >> 16));
            hs.Add((byte)(bodyLen >> 8));
            hs.Add((byte)bodyLen);
            hs.AddRange(pre);
            U16(hs, ext.Count);
            hs.AddRange(ext);

            List<byte> rec = new List<byte>();
            rec.Add(0x16); rec.Add(0x03); rec.Add(0x01);
            U16(rec, hs.Count);
            rec.AddRange(hs);
            return rec.ToArray();
        }
    }

    public class Divert : IDisposable
    {
        private IntPtr handle;
        private Thread worker;
        private volatile bool running;

        public volatile Strategy Cur;   // strategy applied to ClientHello packets; null = pass through
        public string Host;             // host name being tested (used to find the SNI inside the payload)
        public int HellosSeen;
        public int HellosMatched;   // engine mode: ClientHello for a listed host
        public int HellosUnknown;   // engine mode: SNI not found in the first packet (large browser hello)
        public int HellosOther;     // engine mode: ClientHello for a host that is not in the list (passed untouched)
        public int Errors;
        public int SendFail;        // WinDivertSend returned false (packet lost!)
        public int LastSendErr;
        public bool Assemble = true; // engine mode: hold and reassemble ClientHellos that span several packets
        public string[] Hosts;      // engine mode: apply the strategy only to these domains (and subdomains); null = lab mode

        // Engine mode: a ClientHello that does not fit into one TCP packet is held until it is complete.
        private class Pend
        {
            public List<byte[]> Raws = new List<byte[]>();
            public List<byte[]> Addrs = new List<byte[]>();
            public List<byte> Data = new List<byte>();
            public int Need;
            public uint NextSeq;
            public int Ihl;
            public int PayOff;
            public DateTime Born;
        }
        private readonly Dictionary<string, Pend> pending = new Dictionary<string, Pend>();
        private readonly object pendLock = new object();
        private Timer flusher;
        private const int ChunkSize = 1200;

        private Divert() { }

        public static Divert Open(string filter)
        {
            return Create(filter, null);
        }

        public static Divert OpenEngine(string filter, string[] hosts)
        {
            return Create(filter, hosts);
        }

        private static Divert Create(string filter, string[] hosts)
        {
            IntPtr h = Native.WinDivertOpen(filter, 0, 0, 0UL);
            if (h == new IntPtr(-1))
            {
                int err = Marshal.GetLastWin32Error();
                throw new InvalidOperationException("WinDivertOpen failed, error " + err);
            }
            Divert d = new Divert();
            d.handle = h;
            d.Hosts = hosts;
            d.running = true;
            if (hosts != null) d.flusher = new Timer(d.FlushOld, null, 100, 100);
            d.worker = new Thread(d.Loop);
            d.worker.IsBackground = true;
            d.worker.Start();
            return d;
        }

        public void Dispose()
        {
            if (!running) return;
            running = false;
            if (flusher != null) flusher.Dispose();
            ReleaseAll();
            Native.WinDivertClose(handle);
            if (worker != null) worker.Join(1500);
        }

        private void Loop()
        {
            byte[] buf = new byte[65535];
            byte[] addr = new byte[80];
            while (running)
            {
                uint rl;
                if (!Native.WinDivertRecv(handle, buf, (uint)buf.Length, out rl, addr))
                {
                    if (!running) break;
                    Errors++;
                    Thread.Sleep(2);
                    continue;
                }
                try
                {
                    Handle(buf, (int)rl, addr);
                }
                catch (Exception)
                {
                    Errors++;
                    SendRaw(buf, (int)rl, addr);
                }
            }
        }

        private static int ReadU16(byte[] b, int o) { return (b[o] << 8) | b[o + 1]; }
        private static uint ReadU32(byte[] b, int o)
        {
            return ((uint)b[o] << 24) | ((uint)b[o + 1] << 16) | ((uint)b[o + 2] << 8) | (uint)b[o + 3];
        }
        private static void WriteU16(byte[] b, int o, int v) { b[o] = (byte)(v >> 8); b[o + 1] = (byte)v; }
        private static void WriteU32(byte[] b, int o, uint v)
        {
            b[o] = (byte)(v >> 24); b[o + 1] = (byte)(v >> 16); b[o + 2] = (byte)(v >> 8); b[o + 3] = (byte)v;
        }

        private readonly StringBuilder logb = new StringBuilder();
        private int logCount;

        private void Note(string text)
        {
            lock (logb)
            {
                if (logCount >= 300) return;
                logCount++;
                logb.Append(DateTime.Now.ToString("HH:mm:ss.fff")).Append(' ').Append(text).Append("\r\n");
            }
        }

        public string DumpLog()
        {
            lock (logb) { return logb.ToString(); }
        }

        private void SendRaw(byte[] pkt, int len, byte[] addr)
        {
            uint sl;
            if (!Native.WinDivertSend(handle, pkt, (uint)len, out sl, addr))
            {
                SendFail++;
                LastSendErr = Marshal.GetLastWin32Error();
                Note("SEND FAILED (raw) err=" + LastSendErr + " len=" + len);
            }
        }

        private void SendPkt(byte[] pkt, byte[] addr, ulong calcFlags)
        {
            byte[] a = (byte[])addr.Clone();
            Native.WinDivertHelperCalcChecksums(pkt, (uint)pkt.Length, a, calcFlags);
            uint sl;
            if (!Native.WinDivertSend(handle, pkt, (uint)pkt.Length, out sl, a))
            {
                SendFail++;
                LastSendErr = Marshal.GetLastWin32Error();
                Note("SEND FAILED (built) err=" + LastSendErr + " len=" + pkt.Length);
            }
        }

        private void Handle(byte[] buf, int len, byte[] addr)
        {
            Strategy st = Cur;
            if (st != null && len >= 40 && (buf[0] >> 4) == 4 && buf[9] == 6)
            {
                int ihl = (buf[0] & 15) * 4;
                int total = ReadU16(buf, 2);
                if (total > len) total = len;
                if (total >= ihl + 20)
                {
                    int thl = (buf[ihl + 12] >> 4) * 4;
                    int payOff = ihl + thl;
                    int payLen = total - payOff;
                    string key = null;
                    if (Hosts != null)
                    {
                        key = ReadU16(buf, ihl) + ">" + buf[16] + "." + buf[17] + "." + buf[18] + "." + buf[19];
                        if (payLen > 0 && ContinuePending(key, buf, len, addr, ihl, payOff, payLen)) return;
                    }
                    if (payLen > 5 && buf[payOff] == 0x16 && buf[payOff + 1] == 3 && buf[payOff + 5] == 1)
                    {
                        if (Hosts != null)
                        {
                            int need = ReadU16(buf, payOff + 3) + 5;
                            if (Assemble && need > payLen && need <= 6000)
                            {
                                StartPending(key, buf, len, addr, ihl, payOff, payLen, need);
                                return;
                            }
                        }
                        string sni = ParseSni(buf, payOff, payLen);
                        if (Hosts != null)
                        {
                            Note("hello1 sni=" + (sni ?? "-") + " payload=" + payLen + " need=" + (ReadU16(buf, payOff + 3) + 5));
                            if (sni == null) { HellosUnknown++; SendRaw(buf, len, addr); return; }
                            if (!HostMatches(sni)) { HellosOther++; SendRaw(buf, len, addr); return; }
                            HellosMatched++;
                        }
                        HellosSeen++;
                        byte[] hdr = new byte[payOff];
                        Array.Copy(buf, 0, hdr, 0, payOff);
                        byte[] payload = new byte[payLen];
                        Array.Copy(buf, payOff, payload, 0, payLen);
                        byte[] raw = new byte[len];
                        Array.Copy(buf, 0, raw, 0, len);
                        List<byte[]> raws = new List<byte[]>();
                        raws.Add(raw);
                        List<byte[]> addrs = new List<byte[]>();
                        addrs.Add((byte[])addr.Clone());
                        ApplyPayload(st, hdr, ihl, payload, ReadU32(buf, ihl + 4), addr, sni ?? Host, raws, addrs);
                        return;
                    }
                }
            }
            SendRaw(buf, len, addr);
        }

        private void StartPending(string key, byte[] buf, int len, byte[] addr, int ihl, int payOff, int payLen, int need)
        {
            lock (pendLock)
            {
                Pend old;
                if (pending.TryGetValue(key, out old)) { pending.Remove(key); Release(old); }
                Pend p = new Pend();
                byte[] raw = new byte[len];
                Array.Copy(buf, 0, raw, 0, len);
                p.Raws.Add(raw);
                p.Addrs.Add((byte[])addr.Clone());
                byte[] pl = new byte[payLen];
                Array.Copy(buf, payOff, pl, 0, payLen);
                p.Data.AddRange(pl);
                p.Need = need;
                p.NextSeq = unchecked(ReadU32(buf, ihl + 4) + (uint)payLen);
                p.Ihl = ihl;
                p.PayOff = payOff;
                p.Born = DateTime.UtcNow;
                pending[key] = p;
            }
        }

        // Returns true when the packet was consumed as the continuation of a held ClientHello.
        private bool ContinuePending(string key, byte[] buf, int len, byte[] addr, int ihl, int payOff, int payLen)
        {
            lock (pendLock)
            {
                Pend p;
                if (!pending.TryGetValue(key, out p)) return false;
                uint seq = ReadU32(buf, ihl + 4);
                if (seq != p.NextSeq)
                {
                    pending.Remove(key);
                    Release(p);
                    Note("pending: unexpected seq, released");
                    return false;
                }
                byte[] raw = new byte[len];
                Array.Copy(buf, 0, raw, 0, len);
                p.Raws.Add(raw);
                p.Addrs.Add((byte[])addr.Clone());
                byte[] pl = new byte[payLen];
                Array.Copy(buf, payOff, pl, 0, payLen);
                p.Data.AddRange(pl);
                p.NextSeq = unchecked(p.NextSeq + (uint)payLen);
                if (p.Data.Count >= p.Need)
                {
                    pending.Remove(key);
                    Finish(p);
                }
                return true;
            }
        }

        private void Finish(Pend p)
        {
            byte[] full = p.Data.ToArray();
            string sni = ParseSni(full, 0, full.Length);
            Note("hello-assembled sni=" + (sni ?? "-") + " payload=" + full.Length + " packets=" + p.Raws.Count);
            Strategy st = Cur;
            if (st == null || sni == null || !HostMatches(sni))
            {
                if (sni == null) HellosUnknown++; else HellosOther++;
                Release(p);
                return;
            }
            HellosMatched++;
            HellosSeen++;
            byte[] first = p.Raws[0];
            byte[] hdr = new byte[p.PayOff];
            Array.Copy(first, 0, hdr, 0, p.PayOff);
            ApplyPayload(st, hdr, p.Ihl, full, ReadU32(first, p.Ihl + 4), p.Addrs[0], sni, p.Raws, p.Addrs);
        }

        private void Release(Pend p)
        {
            for (int i = 0; i < p.Raws.Count; i++) SendRaw(p.Raws[i], p.Raws[i].Length, p.Addrs[i]);
        }

        private void ReleaseAll()
        {
            lock (pendLock)
            {
                foreach (KeyValuePair<string, Pend> kv in pending) Release(kv.Value);
                pending.Clear();
            }
        }

        private void FlushOld(object state)
        {
            try
            {
                lock (pendLock)
                {
                    if (pending.Count == 0) return;
                    List<string> dead = new List<string>();
                    DateTime now = DateTime.UtcNow;
                    foreach (KeyValuePair<string, Pend> kv in pending)
                    {
                        if ((now - kv.Value.Born).TotalMilliseconds > 300) dead.Add(kv.Key);
                    }
                    foreach (string k in dead)
                    {
                        Pend p = pending[k];
                        pending.Remove(k);
                        Release(p);
                        HellosUnknown++;
                        Note("pending: timeout, released");
                    }
                }
            }
            catch (Exception) { }
        }

        private bool HostMatches(string sni)
        {
            foreach (string h in Hosts)
            {
                if (sni == h || sni.EndsWith("." + h)) return true;
            }
            return false;
        }

        // Extracts the server name from a TLS ClientHello that starts at b[off] (record header included).
        private static string ParseSni(byte[] b, int off, int len)
        {
            try
            {
                int end = off + len;
                int p = off + 5;
                if (p + 4 > end || b[p] != 1) return null;
                p += 4;
                p += 2 + 32;
                if (p >= end) return null;
                p += 1 + b[p];
                if (p + 2 > end) return null;
                p += 2 + ((b[p] << 8) | b[p + 1]);
                if (p >= end) return null;
                p += 1 + b[p];
                if (p + 2 > end) return null;
                int el = (b[p] << 8) | b[p + 1];
                p += 2;
                int eend = Math.Min(end, p + el);
                while (p + 4 <= eend)
                {
                    int et = (b[p] << 8) | b[p + 1];
                    int elen = (b[p + 2] << 8) | b[p + 3];
                    p += 4;
                    if (et == 0)
                    {
                        if (p + 5 > end) return null;
                        int nl = (b[p + 3] << 8) | b[p + 4];
                        if (nl <= 0 || p + 5 + nl > end) return null;
                        return Encoding.ASCII.GetString(b, p + 5, nl).ToLowerInvariant();
                    }
                    p += elen;
                }
            }
            catch (Exception) { }
            return null;
        }

        private static int IndexOf(byte[] hay, byte[] needle)
        {
            if (needle == null || needle.Length == 0) return -1;
            for (int i = 0; i + needle.Length <= hay.Length; i++)
            {
                bool ok = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (hay[i + j] != needle[j]) { ok = false; break; }
                }
                if (ok) return i;
            }
            return -1;
        }

        private int SplitPoint(Strategy st, byte[] payload, string host)
        {
            if (st.SplitPos > 0) return st.SplitPos;
            if (string.IsNullOrEmpty(host)) return payload.Length / 2;
            int sni = IndexOf(payload, Encoding.ASCII.GetBytes(host));
            if (sni < 0) return payload.Length / 2;       // name is in a later packet of a large hello: split the middle
            if (st.SplitPos == -2) return sni;
            return sni + (host.Length / 2);
        }

        private static byte[] MakeSeg(byte[] hdr, int ihl, byte[] data, int off, int cnt, uint seq, int ttl, bool last, bool md5, bool badsum, int ipid)
        {
            if (md5 && (hdr.Length - ihl) > 40) md5 = false;       // no room for one more TCP option
            int extra = md5 ? 20 : 0;
            byte[] p = new byte[hdr.Length + extra + cnt];
            Array.Copy(hdr, 0, p, 0, hdr.Length);
            if (md5)
            {
                int o = hdr.Length;
                p[o] = 19; p[o + 1] = 18;                           // TCP option kind 19 (MD5 signature), length 18, 16 zero bytes
                p[o + 18] = 1; p[o + 19] = 1;                       // two NOPs for 4-byte alignment
                int doff = (p[ihl + 12] >> 4) + 5;
                p[ihl + 12] = (byte)((doff << 4) | (p[ihl + 12] & 0x0F));
            }
            Array.Copy(data, off, p, hdr.Length + extra, cnt);
            WriteU16(p, 2, p.Length);
            WriteU16(p, 4, ipid & 0xFFFF);
            if (ttl > 0) p[8] = (byte)ttl;
            WriteU32(p, ihl + 4, seq);
            if (!last) p[ihl + 13] = (byte)(p[ihl + 13] & ~0x09);   // clear PSH and FIN on the first part
            p[10] = 0; p[11] = 0;                                   // IP checksum (recomputed by WinDivert helper)
            p[ihl + 16] = 0; p[ihl + 17] = 0;                       // TCP checksum
            if (badsum) { p[ihl + 16] = 0xDE; p[ihl + 17] = 0xAD; } // deliberately wrong, helper is told not to fix it
            return p;
        }

        private List<byte[]> Chunks(byte[] hdr, int ihl, byte[] payload, int start, int count, uint seq, ref int idc, bool lastPart)
        {
            List<byte[]> res = new List<byte[]>();
            int off = 0;
            while (off < count)
            {
                int n = Math.Min(ChunkSize, count - off);
                bool last = lastPart && (off + n >= count);
                idc++;
                res.Add(MakeSeg(hdr, ihl, payload, start + off, n, unchecked(seq + (uint)(start + off)), 0, last, false, false, idc));
                off += n;
            }
            return res;
        }

        // payload = the complete ClientHello (one or several original packets); raws/addrs = the original packets.
        private void ApplyPayload(Strategy st, byte[] hdr, int ihl, byte[] payload, uint seq, byte[] addr, string host, List<byte[]> raws, List<byte[]> addrs)
        {
            int idc = ReadU16(hdr, 4);

            if (st.FakeRepeats > 0)
            {
                string fsni = string.IsNullOrEmpty(st.FakeSni) ? "www.google.com" : st.FakeSni;
                byte[] fake = Hello.Build(fsni);
                uint fseq = st.FakeBadSeq ? unchecked(seq - 100000u) : seq;
                ulong cf = st.FakeBadSum ? 8UL : 0UL;           // 8 = WINDIVERT_HELPER_NO_TCP_CHECKSUM
                for (int i = 0; i < st.FakeRepeats; i++)
                {
                    idc++;
                    SendPkt(MakeSeg(hdr, ihl, fake, 0, fake.Length, fseq, st.FakeTtl, true, st.FakeMd5, st.FakeBadSum, idc), addr, cf);
                }
            }

            if (st.Split == "split" || st.Split == "disorder")
            {
                int pos = SplitPoint(st, payload, host);
                if (pos < 1 || pos >= payload.Length) pos = 1;
                Note("apply " + st.Name + " host=" + host + " payload=" + payload.Length + " pos=" + pos);
                List<byte[]> a = Chunks(hdr, ihl, payload, 0, pos, seq, ref idc, false);
                List<byte[]> b = Chunks(hdr, ihl, payload, pos, payload.Length - pos, seq, ref idc, true);
                if (st.Split == "disorder")
                {
                    foreach (byte[] x in b) SendPkt(x, addr, 0UL);
                    foreach (byte[] x in a) SendPkt(x, addr, 0UL);
                }
                else
                {
                    foreach (byte[] x in a) SendPkt(x, addr, 0UL);
                    foreach (byte[] x in b) SendPkt(x, addr, 0UL);
                }
            }
            else
            {
                for (int i = 0; i < raws.Count; i++) SendRaw(raws[i], raws[i].Length, addrs[i]);
            }
        }
    }

    // Silently drops packets matching the filter (used to push browsers from QUIC back to TCP for Google IPs).
    public class Dropper : IDisposable
    {
        private IntPtr handle;
        private bool open;

        public static Dropper Open(string filter)
        {
            IntPtr h = Native.WinDivertOpen(filter, 0, 0, 2UL);   // 2 = WINDIVERT_FLAG_DROP
            if (h == new IntPtr(-1))
            {
                throw new InvalidOperationException("WinDivertOpen failed, error " + Marshal.GetLastWin32Error());
            }
            Dropper d = new Dropper();
            d.handle = h;
            d.open = true;
            return d;
        }

        public void Dispose()
        {
            if (!open) return;
            open = false;
            Native.WinDivertClose(handle);
        }
    }

    public static class Lab
    {
        // Sends a large ClientHello over a plain socket (the OS splits it into several TCP packets, like a browser does)
        // and reports whether the server answered with a TLS record: OK / RESET / TIMEOUT / CLOSED / STUB / ERR.
        public static string RawHelloProbe(string ip, string sni, int padTo, bool sniLast, int timeoutMs)
        {
            byte[] hello = Hello.Build(sni, padTo, sniLast);
            TcpClient c = new TcpClient();
            c.NoDelay = true;
            try
            {
                IAsyncResult iar = c.BeginConnect(IPAddress.Parse(ip), 443, null, null);
                if (!iar.AsyncWaitHandle.WaitOne(timeoutMs)) return "NOCONN";
                c.EndConnect(iar);
                NetworkStream ns = c.GetStream();
                ns.ReadTimeout = timeoutMs;
                ns.WriteTimeout = timeoutMs;
                ns.Write(hello, 0, hello.Length);
                byte[] b = new byte[16];
                int n = ns.Read(b, 0, b.Length);
                if (n <= 0) return "CLOSED";
                if (b[0] == 0x16 || b[0] == 0x15) return "OK";
                return "STUB";
            }
            catch (Exception ex)
            {
                Exception e = ex;
                while (e != null && !(e is SocketException)) e = e.InnerException;
                if (e != null)
                {
                    string code = ((SocketException)e).SocketErrorCode.ToString();
                    if (code == "TimedOut") return "TIMEOUT";
                    if (code == "ConnectionReset" || code == "ConnectionAborted") return "RESET";
                }
                return "ERR";
            }
            finally { c.Close(); }
        }

        public static Strategy FindByName(string name)
        {
            foreach (Strategy s in BuildMatrix(false))
            {
                if (s.Name == name) return s;
            }
            return null;
        }

        public static string Init(string dllPath)
        {
            IntPtr h = Native.LoadLibrary(dllPath);
            if (h == IntPtr.Zero) return "LoadLibrary failed, error " + Marshal.GetLastWin32Error();
            return null;
        }

        public static bool TcpOk(string ip, int port, int ms)
        {
            TcpClient c = new TcpClient();
            try
            {
                IAsyncResult iar = c.BeginConnect(IPAddress.Parse(ip), port, null, null);
                if (!iar.AsyncWaitHandle.WaitOne(ms)) return false;
                c.EndConnect(iar);
                return true;
            }
            catch (Exception) { return false; }
            finally { c.Close(); }
        }

        // Full check: TCP connect, TLS handshake with SNI = host, certificate valid for host, HTTP answer received.
        public static TestResult TestOne(string ip, string host, int timeoutMs)
        {
            TestResult r = new TestResult();
            r.Stage = "tcp";
            r.Error = "";
            Stopwatch sw = Stopwatch.StartNew();
            TcpClient c = new TcpClient();
            try
            {
                c.NoDelay = true;
                IAsyncResult iar = c.BeginConnect(IPAddress.Parse(ip), 443, null, null);
                if (!iar.AsyncWaitHandle.WaitOne(timeoutMs)) { r.Error = "TCP: timeout"; return r; }
                c.EndConnect(iar);
                r.Stage = "tls";
                NetworkStream ns = c.GetStream();
                ns.ReadTimeout = timeoutMs;
                ns.WriteTimeout = timeoutMs;
                string policy = "None";
                RemoteCertificateValidationCallback cb = delegate(object s, X509Certificate cert, X509Chain chain, SslPolicyErrors err)
                {
                    policy = err.ToString();
                    return true;
                };
                using (SslStream ssl = new SslStream(ns, false, cb))
                {
                    ssl.AuthenticateAsClient(host, null, SslProtocols.Tls12, false);
                    if (policy != "None") { r.Error = "certificate: " + policy; return r; }
                    r.Stage = "http";
                    byte[] req = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n");
                    ssl.Write(req, 0, req.Length);
                    byte[] rb = new byte[256];
                    int n = ssl.Read(rb, 0, rb.Length);
                    if (n >= 5 && Encoding.ASCII.GetString(rb, 0, 5) == "HTTP/")
                    {
                        r.Ok = true;
                        r.Stage = "ok";
                    }
                    else
                    {
                        r.Error = "no HTTP answer";
                    }
                }
            }
            catch (Exception ex)
            {
                Exception e = ex;
                while (e.InnerException != null) e = e.InnerException;
                r.Error = e.Message;
            }
            finally
            {
                r.Ms = (int)sw.ElapsedMilliseconds;
                c.Close();
            }
            return r;
        }

        private static Strategy Mk(string split, int pos, int repeats, int ttl, bool badseq, bool md5, bool badsum)
        {
            Strategy s = new Strategy();
            s.Split = split;
            s.SplitPos = pos;
            s.FakeRepeats = repeats;
            s.FakeTtl = ttl;
            s.FakeBadSeq = badseq;
            s.FakeMd5 = md5;
            s.FakeBadSum = badsum;
            s.FakeSni = "www.google.com";
            string n = "";
            if (repeats > 0)
            {
                if (badseq) n = "fake(badseq,x" + repeats + ")";
                else if (md5) n = "fake(md5sig,x" + repeats + ")";
                else if (badsum) n = "fake(badsum,x" + repeats + ")";
                else n = "fake(ttl=" + ttl + ",x" + repeats + ")";
                n += " + ";
            }
            if (split == "none") n += "no-split";
            else n += split + "@" + (pos > 0 ? pos.ToString() : (pos == -1 ? "host-mid" : "host-start"));
            s.Name = n;
            return s;
        }

        public static Strategy[] BuildMatrix(bool quick)
        {
            List<Strategy> l = new List<Strategy>();
            // 1. Pure packet manipulation, no fake packets
            l.Add(Mk("split", 1, 0, 0, false, false, false));
            l.Add(Mk("split", -1, 0, 0, false, false, false));
            l.Add(Mk("disorder", 1, 0, 0, false, false, false));
            l.Add(Mk("disorder", -1, 0, 0, false, false, false));

            // 2. Fake ClientHello with a harmless name, hidden from the server by TTL / bad seq / MD5 option / bad checksum
            int[] ttls = quick ? new int[] { 3, 5 } : new int[] { 2, 3, 4, 5, 6, 8 };
            int[] reps = quick ? new int[] { 1 } : new int[] { 1, 4 };
            string[] splits = quick ? new string[] { "none", "disorder" } : new string[] { "none", "split", "disorder" };
            int[] poss = quick ? new int[] { -1 } : new int[] { 1, -1 };

            foreach (int rep in reps)
            {
                foreach (string sp in splits)
                {
                    foreach (int ps in poss)
                    {
                        if (sp == "none" && ps != poss[0]) continue;   // no-split needs only one entry
                        int pp = (sp == "none") ? 0 : ps;
                        l.Add(Mk(sp, pp, rep, 0, false, true, false));     // md5sig
                        l.Add(Mk(sp, pp, rep, 0, false, false, true));     // badsum
                        l.Add(Mk(sp, pp, rep, 0, true, false, false));     // badseq
                        foreach (int t in ttls) l.Add(Mk(sp, pp, rep, t, false, false, false));
                    }
                }
            }
            return l.ToArray();
        }
    }
}
