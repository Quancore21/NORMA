// NORMA engine core, pure computation (no network, no driver), so it can be tested anywhere:
//   Planner:        which packets a bypass technique would send for a given TLS ClientHello (tools/engine_ref.py, tests/engine-golden.json)
//   PacketBuilder:  real IPv4+TCP bytes for that plan, with fooling (tools/packet_ref.py, tests/packet-golden.json)
// Keep this file ASCII-only and C# 5 compatible: it is compiled by Add-Type in Windows PowerShell 5.1.
using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace NormaCore
{
    public class HelloInfo
    {
        public bool Ok;
        public int SniOffset;
        public int SniLength;
        public string Host = "";
        public int Size;
    }

    public class PlanPacket
    {
        public string Kind;    // "fake" or "data"
        public int Offset;     // data: offset in the original payload
        public int Length;     // fake: length of the fake payload (0 = built-in or unknown); data: segment length
        public int Extra;      // fake: number of repeats; data: seqovl overlap in bytes
    }

    public class Plan
    {
        public List<PlanPacket> Packets = new List<PlanPacket>();
        public List<string> Unsupported = new List<string>();
        public string Fooling = "";
        public int PayloadLength;
    }

    public static class Planner
    {
        private static int U16(byte[] d, int p)
        {
            return (d[p] << 8) | d[p + 1];
        }

        private static void AddUnique(List<string> list, string item)
        {
            if (!list.Contains(item)) list.Add(item);
        }

        private static PlanPacket Pkt(string kind, int offset, int length, int extra)
        {
            PlanPacket k = new PlanPacket();
            k.Kind = kind;
            k.Offset = offset;
            k.Length = length;
            k.Extra = extra;
            return k;
        }

        // Strict parse of a TLS ClientHello: every length is checked against the boundary of its own structure
        // (record, handshake message, extension list, extension, name). Any inconsistency returns a result without SNI.
        // The same rules are in tools/engine_ref.py (strict_parse); the golden tests cover truncated and contradictory inputs.
        public static HelloInfo ParseHello(byte[] d)
        {
            HelloInfo h = new HelloInfo();
            h.Size = d.Length;
            try
            {
                if (d.Length < 5 || d[0] != 0x16) return h;
                int recEnd = 5 + U16(d, 3);
                if (recEnd > d.Length) return h;
                int pos = 5;
                if (pos + 4 > recEnd || d[pos] != 0x01) return h;
                int hsEnd = pos + 4 + ((d[pos + 1] << 16) | (d[pos + 2] << 8) | d[pos + 3]);
                if (hsEnd != recEnd) return h;
                pos += 4;
                if (pos + 2 + 32 > hsEnd) return h;
                pos += 2 + 32;
                if (pos + 1 > hsEnd) return h;
                pos += 1 + d[pos];
                if (pos + 2 > hsEnd) return h;
                pos += 2 + U16(d, pos);
                if (pos + 1 > hsEnd) return h;
                pos += 1 + d[pos];
                if (pos + 2 > hsEnd) return h;
                int extEnd = pos + 2 + U16(d, pos);
                pos += 2;
                if (extEnd != hsEnd) return h;
                bool seen = false;
                int sniStart = 0;
                int sniLen = 0;
                while (pos < extEnd)
                {
                    if (pos + 4 > extEnd) return h;
                    int type = U16(d, pos);
                    int len = U16(d, pos + 2);
                    int dataStart = pos + 4;
                    int dataEnd = dataStart + len;
                    if (dataEnd > extEnd) return h;
                    if (type == 0)
                    {
                        if (seen) return h;
                        seen = true;
                        if (len < 5) return h;
                        int listLen = U16(d, dataStart);
                        if (2 + listLen != len) return h;
                        if (d[dataStart + 2] != 0) return h;
                        int nlen = U16(d, dataStart + 3);
                        if (nlen == 0 || 3 + nlen != listLen) return h;
                        sniStart = dataStart + 5;
                        sniLen = nlen;
                    }
                    pos = dataEnd;
                }
                if (!seen) return h;
                h.SniOffset = sniStart;
                h.SniLength = sniLen;
                h.Host = Encoding.ASCII.GetString(d, sniStart, sniLen);
                h.Ok = true;
            }
            catch (Exception)
            {
                h = new HelloInfo();
                h.Size = d.Length;
            }
            return h;
        }

        // Canonical text form of the parse result (used by the golden tests).
        public static string DescribeHello(byte[] d)
        {
            HelloInfo h = ParseHello(d);
            if (!h.Ok) return "Ok:0";
            return "Ok:1;off:" + h.SniOffset.ToString() + ";len:" + h.SniLength.ToString() + ";host:" + h.Host;
        }

        // Middle of the second-level domain: www.google.com -> middle of "google".
        private static int MidSld(HelloInfo h)
        {
            string[] labels = h.Host.Split('.');
            if (labels.Length < 2) return h.SniOffset + h.SniLength / 2;
            int start = 0;
            for (int i = 0; i < labels.Length - 2; i++) start += labels[i].Length + 1;
            string sld = labels[labels.Length - 2];
            return h.SniOffset + start + sld.Length / 2;
        }

        // Split positions: numbers, and host / endhost / midsld with an optional +N or -N.
        // Other markers are not modeled and are reported through the unsupported list.
        public static List<int> ResolvePositions(byte[] d, string spec, List<string> unsupported)
        {
            List<int> res = new List<int>();
            HelloInfo h = null;
            string[] parts = (spec == null ? "" : spec).Split(',');
            foreach (string part in parts)
            {
                string p = part.Trim();
                if (p.Length == 0) continue;
                long value = -1;
                if (Regex.IsMatch(p, "^[0-9]{1,9}$"))
                {
                    value = long.Parse(p);
                }
                else
                {
                    Match m = Regex.Match(p, "^([a-z]+)([+-][0-9]{1,9})?$");
                    if (!m.Success)
                    {
                        AddUnique(unsupported, p);
                        continue;
                    }
                    string name = m.Groups[1].Value;
                    long delta = 0;
                    if (m.Groups[2].Success) delta = long.Parse(m.Groups[2].Value);
                    if (h == null) h = ParseHello(d);
                    long baseValue = -1;
                    if (name == "host" && h.Ok) baseValue = h.SniOffset;
                    else if (name == "endhost" && h.Ok) baseValue = h.SniOffset + h.SniLength;
                    else if (name == "midsld" && h.Ok) baseValue = MidSld(h);
                    else
                    {
                        AddUnique(unsupported, name);
                        continue;
                    }
                    value = baseValue + delta;
                }
                if (value > 0 && value < d.Length)
                {
                    int v = (int)value;
                    if (!res.Contains(v)) res.Add(v);
                }
            }
            res.Sort();
            return res;
        }

        public static string DescribePositions(byte[] d, string spec)
        {
            List<string> un = new List<string>();
            List<int> pos = ResolvePositions(d, spec, un);
            StringBuilder sb = new StringBuilder();
            sb.Append("P:");
            for (int i = 0; i < pos.Count; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append(pos[i].ToString());
            }
            if (un.Count > 0) sb.Append("|U:").Append(string.Join(",", un.ToArray()));
            return sb.ToString();
        }

        // Builds the packet plan. Modes: fake, multisplit, multidisorder are modeled; anything else is reported as unsupported.
        public static Plan Build(byte[] d, string modes, string splitPos, int seqovl, int repeats, string fooling, int fakeLen)
        {
            Plan plan = new Plan();
            plan.PayloadLength = d.Length;
            plan.Fooling = (fooling == null) ? "" : fooling;
            List<string> ml = new List<string>();
            foreach (string m in (modes == null ? "" : modes).Split(','))
            {
                string t = m.Trim();
                if (t.Length > 0) ml.Add(t);
            }
            bool hasFake = ml.Contains("fake");
            bool disorder = ml.Contains("multidisorder");
            bool split = ml.Contains("multisplit") || disorder;
            foreach (string m in ml)
            {
                if (m != "fake" && m != "multisplit" && m != "multidisorder") AddUnique(plan.Unsupported, m);
            }
            if (hasFake) plan.Packets.Add(Pkt("fake", 0, fakeLen, repeats > 0 ? repeats : 1));

            List<int> pos = new List<int>();
            if (split)
            {
                List<string> un = new List<string>();
                pos = ResolvePositions(d, splitPos, un);
                foreach (string u in un) AddUnique(plan.Unsupported, "pos:" + u);
            }
            if (split && pos.Count > 0)
            {
                List<int> bounds = new List<int>();
                bounds.Add(0);
                bounds.AddRange(pos);
                bounds.Add(d.Length);
                List<PlanPacket> segs = new List<PlanPacket>();
                for (int i = 0; i < bounds.Count - 1; i++)
                {
                    segs.Add(Pkt("data", bounds[i], bounds[i + 1] - bounds[i], i == 0 ? seqovl : 0));
                }
                if (disorder) segs.Reverse();
                plan.Packets.AddRange(segs);
            }
            else
            {
                if (split) AddUnique(plan.Unsupported, "split-pos:none");
                plan.Packets.Add(Pkt("data", 0, d.Length, 0));
            }
            return plan;
        }

        // Canonical text form, identical in tools/engine_ref.py (used by the golden tests).
        public static string Describe(Plan p)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < p.Packets.Count; i++)
            {
                if (i > 0) sb.Append(';');
                PlanPacket k = p.Packets[i];
                sb.Append(k.Kind).Append(':').Append(k.Offset.ToString()).Append(':').Append(k.Length.ToString()).Append(':').Append(k.Extra.ToString());
            }
            if (p.Unsupported.Count > 0) sb.Append("|U:").Append(string.Join(",", p.Unsupported.ToArray()));
            if (p.Fooling.Length > 0) sb.Append("|F:").Append(p.Fooling);
            return sb.ToString();
        }

        public static string DescribePlan(byte[] d, string modes, string splitPos, int seqovl, int repeats, string fooling, int fakeLen)
        {
            return Describe(Build(d, modes, splitPos, seqovl, repeats, fooling, fakeLen));
        }
    }

    public class BuiltPacket
    {
        public string Kind;       // "fake" or "data"
        public byte[] Bytes;      // the whole IPv4+TCP packet
        public int SeqRel;        // sequence number relative to the original packet (signed 32-bit difference)
        public int PayloadLen;
        public int Flags;
        public int Ttl;
        public int Id;
        public bool ChecksumOk;
    }

    public class PacketSet
    {
        public List<BuiltPacket> Packets = new List<BuiltPacket>();
        public List<string> Notes = new List<string>();
    }

    // Builds real IPv4+TCP packets from a plan. Definitions are NORMA's (see tools/packet_ref.py), not a copy of winws.
    public static class PacketBuilder
    {
        public const int TsDelta = 600000;

        private class Tpl
        {
            public byte[] Raw;
            public int Ihl;
            public int Total;
            public int Id;
            public int Ttl;
            public int Tcp;
            public uint Seq;
            public int Thl;
            public int Flags;
            public byte[] Opts;
            public byte[] Payload;
        }

        private static int Csum16(byte[] data)
        {
            long s = 0;
            int n = data.Length;
            for (int i = 0; i + 1 < n; i += 2) s += (data[i] << 8) | data[i + 1];
            if ((n & 1) == 1) s += data[n - 1] << 8;
            while ((s >> 16) != 0) s = (s & 0xFFFF) + (s >> 16);
            return (int)((~s) & 0xFFFF);
        }

        private static byte[] Cat(byte[] a, byte[] b, byte[] c)
        {
            byte[] r = new byte[a.Length + b.Length + c.Length];
            Array.Copy(a, 0, r, 0, a.Length);
            Array.Copy(b, 0, r, a.Length, b.Length);
            Array.Copy(c, 0, r, a.Length + b.Length, c.Length);
            return r;
        }

        private static byte[] Slice(byte[] d, int off, int len)
        {
            byte[] r = new byte[len];
            Array.Copy(d, off, r, 0, len);
            return r;
        }

        private static void AddNote(List<string> notes, string n)
        {
            if (!notes.Contains(n)) notes.Add(n);
        }

        private static Tpl ParseTpl(byte[] pkt)
        {
            if (pkt.Length < 40 || (pkt[0] >> 4) != 4 || pkt[9] != 6) throw new ArgumentException("not an IPv4 TCP packet");
            Tpl t = new Tpl();
            t.Ihl = (pkt[0] & 15) * 4;
            t.Total = (pkt[2] << 8) | pkt[3];
            if (t.Total > pkt.Length || t.Total < t.Ihl + 20) throw new ArgumentException("bad IP length");
            t.Tcp = t.Ihl;
            t.Thl = (pkt[t.Tcp + 12] >> 4) * 4;
            if (t.Thl < 20 || t.Tcp + t.Thl > t.Total) throw new ArgumentException("bad TCP header length");
            t.Raw = Slice(pkt, 0, t.Total);
            t.Id = (pkt[4] << 8) | pkt[5];
            t.Ttl = pkt[8];
            t.Seq = ((uint)pkt[t.Tcp + 4] << 24) | ((uint)pkt[t.Tcp + 5] << 16) | ((uint)pkt[t.Tcp + 6] << 8) | (uint)pkt[t.Tcp + 7];
            t.Flags = pkt[t.Tcp + 13];
            t.Opts = Slice(pkt, t.Tcp + 20, t.Thl - 20);
            t.Payload = Slice(pkt, t.Tcp + t.Thl, t.Total - t.Tcp - t.Thl);
            return t;
        }

        private static byte[] BuildOne(Tpl t, byte[] payload, uint seq, int flags, int ttl, int ipid, byte[] opts, bool badChecksum)
        {
            int thl = 20 + opts.Length;
            byte[] ip = Slice(t.Raw, 0, t.Ihl);
            byte[] tcp = Slice(t.Raw, t.Tcp, 20);
            tcp[12] = (byte)(((thl / 4) << 4) | (t.Raw[t.Tcp + 12] & 0x0F));
            tcp[13] = (byte)(flags & 0xFF);
            tcp[4] = (byte)((seq >> 24) & 0xFF);
            tcp[5] = (byte)((seq >> 16) & 0xFF);
            tcp[6] = (byte)((seq >> 8) & 0xFF);
            tcp[7] = (byte)(seq & 0xFF);
            tcp[16] = 0;
            tcp[17] = 0;
            byte[] seg = Cat(tcp, opts, payload);
            int total = t.Ihl + seg.Length;
            ip[2] = (byte)((total >> 8) & 0xFF);
            ip[3] = (byte)(total & 0xFF);
            ip[4] = (byte)((ipid >> 8) & 0xFF);
            ip[5] = (byte)(ipid & 0xFF);
            ip[8] = (byte)(ttl & 0xFF);
            ip[10] = 0;
            ip[11] = 0;
            byte[] pseudo = new byte[12 + seg.Length];
            Array.Copy(ip, 12, pseudo, 0, 8);
            pseudo[8] = 0;
            pseudo[9] = 6;
            pseudo[10] = (byte)((seg.Length >> 8) & 0xFF);
            pseudo[11] = (byte)(seg.Length & 0xFF);
            Array.Copy(seg, 0, pseudo, 12, seg.Length);
            int cs = Csum16(pseudo);
            if (badChecksum) cs = (cs + 1) & 0xFFFF;
            seg[16] = (byte)((cs >> 8) & 0xFF);
            seg[17] = (byte)(cs & 0xFF);
            int ics = Csum16(ip);
            ip[10] = (byte)((ics >> 8) & 0xFF);
            ip[11] = (byte)(ics & 0xFF);
            return Cat(ip, seg, new byte[0]);
        }

        // True if both checksums of a packet are valid (independent re-check)
        public static bool Verify(byte[] pkt)
        {
            int ihl = (pkt[0] & 15) * 4;
            if (Csum16(Slice(pkt, 0, ihl)) != 0) return false;
            int total = (pkt[2] << 8) | pkt[3];
            int segLen = total - ihl;
            byte[] pseudo = new byte[12 + segLen];
            Array.Copy(pkt, 12, pseudo, 0, 8);
            pseudo[8] = 0;
            pseudo[9] = 6;
            pseudo[10] = (byte)((segLen >> 8) & 0xFF);
            pseudo[11] = (byte)(segLen & 0xFF);
            Array.Copy(pkt, ihl, pseudo, 12, segLen);
            return Csum16(pseudo) == 0;
        }

        private static byte[] StripEol(byte[] opts)
        {
            int i = 0;
            int n = opts.Length;
            while (i < n)
            {
                int k = opts[i];
                if (k == 0) return Slice(opts, 0, i);
                if (k == 1) { i++; continue; }
                if (i + 1 >= n || opts[i + 1] < 2) break;
                i += opts[i + 1];
            }
            return opts;
        }

        private static bool BadTimestamp(byte[] opts, out byte[] result)
        {
            byte[] b = (byte[])opts.Clone();
            int i = 0;
            int n = b.Length;
            while (i < n)
            {
                int k = b[i];
                if (k == 0) break;
                if (k == 1) { i++; continue; }
                if (i + 1 >= n || b[i + 1] < 2) break;
                int ln = b[i + 1];
                if (k == 8 && ln == 10 && i + 10 <= n)
                {
                    uint v = ((uint)b[i + 2] << 24) | ((uint)b[i + 3] << 16) | ((uint)b[i + 4] << 8) | (uint)b[i + 5];
                    v = unchecked(v - (uint)TsDelta);
                    b[i + 2] = (byte)((v >> 24) & 0xFF);
                    b[i + 3] = (byte)((v >> 16) & 0xFF);
                    b[i + 4] = (byte)((v >> 8) & 0xFF);
                    b[i + 5] = (byte)(v & 0xFF);
                    result = b;
                    return true;
                }
                i += ln;
            }
            result = opts;
            return false;
        }

        private static bool AddMd5(byte[] opts, out byte[] result)
        {
            List<byte> l = new List<byte>(StripEol(opts));
            l.Add(19);
            l.Add(18);
            for (int i = 0; i < 16; i++) l.Add(0);
            while (l.Count % 4 != 0) l.Add(1);
            if (l.Count > 40)
            {
                result = opts;
                return false;
            }
            result = l.ToArray();
            return true;
        }

        private static BuiltPacket Make(string kind, byte[] raw, uint seq, uint origSeq, int payloadLen, int flags, int ttl, int id)
        {
            BuiltPacket b = new BuiltPacket();
            b.Kind = kind;
            b.Bytes = raw;
            b.SeqRel = unchecked((int)(seq - origSeq));
            b.PayloadLen = payloadLen;
            b.Flags = flags;
            b.Ttl = ttl;
            b.Id = id;
            b.ChecksumOk = Verify(raw);
            return b;
        }

        // Builds packets for a plan. pkt is the original IPv4+TCP packet carrying the ClientHello.
        public static PacketSet Build(byte[] pkt, string modes, string splitPos, int seqovl, int repeats, string fooling,
            byte[] fakePayload, byte[] pattern, int ttl, int badseqInc, bool ipidZero, bool fakeMod)
        {
            Tpl t = ParseTpl(pkt);
            Plan plan = Planner.Build(t.Payload, modes, splitPos, seqovl, repeats, fooling, fakePayload.Length);
            PacketSet set = new PacketSet();
            foreach (string u in plan.Unsupported) AddNote(set.Notes, u);
            List<string> foo = new List<string>();
            foreach (string f in (fooling == null ? "" : fooling).Split(','))
            {
                string x = f.Trim();
                if (x.Length > 0) foo.Add(x);
            }
            foreach (string f in foo)
            {
                if (f != "badsum" && f != "badseq" && f != "md5sig" && f != "ts") AddNote(set.Notes, "fooling:" + f);
            }
            if (fakeMod) AddNote(set.Notes, "fake-tls-mod");
            foreach (PlanPacket p in plan.Packets)
            {
                if (p.Kind == "fake")
                {
                    for (int r = 0; r < p.Extra; r++)
                    {
                        int i = set.Packets.Count;
                        uint seq = t.Seq;
                        if (foo.Contains("badseq")) seq = unchecked(seq + (uint)badseqInc);
                        byte[] opts = t.Opts;
                        if (foo.Contains("ts"))
                        {
                            byte[] o2;
                            if (BadTimestamp(opts, out o2)) opts = o2; else AddNote(set.Notes, "ts-no-option");
                        }
                        if (foo.Contains("md5sig"))
                        {
                            byte[] o3;
                            if (AddMd5(opts, out o3)) opts = o3; else AddNote(set.Notes, "md5sig-overflow");
                        }
                        int pttl = ttl > 0 ? ttl : t.Ttl;
                        int pid = ipidZero ? 0 : ((t.Id + i) & 0xFFFF);
                        byte[] raw = BuildOne(t, fakePayload, seq, t.Flags, pttl, pid, opts, foo.Contains("badsum"));
                        set.Packets.Add(Make("fake", raw, seq, t.Seq, fakePayload.Length, t.Flags, pttl, pid));
                    }
                }
                else
                {
                    int i2 = set.Packets.Count;
                    byte[] body = Slice(t.Payload, p.Offset, p.Length);
                    uint seq2 = unchecked(t.Seq + (uint)p.Offset);
                    if (p.Extra > 0)
                    {
                        byte[] pre = new byte[p.Extra];
                        int copy = Math.Min(pattern.Length, p.Extra);
                        Array.Copy(pattern, 0, pre, 0, copy);
                        body = Cat(pre, body, new byte[0]);
                        seq2 = unchecked(seq2 - (uint)p.Extra);
                    }
                    int flags = t.Flags;
                    if ((t.Flags & 8) != 0)
                    {
                        bool psh = (p.Offset + p.Length == t.Payload.Length);
                        flags = (t.Flags & ~8) | (psh ? 8 : 0);
                    }
                    int pid2 = ipidZero ? 0 : ((t.Id + i2) & 0xFFFF);
                    byte[] raw2 = BuildOne(t, body, seq2, flags, t.Ttl, pid2, t.Opts, false);
                    set.Packets.Add(Make("data", raw2, seq2, t.Seq, body.Length, flags, t.Ttl, pid2));
                }
            }
            return set;
        }

        public static string Sha256Hex(byte[] data)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] h = sha.ComputeHash(data);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < h.Length; i++) sb.Append(h[i].ToString("x2"));
                return sb.ToString();
            }
        }

        // Canonical text form, identical in tools/packet_ref.py (used by the golden tests).
        public static string Describe(PacketSet s)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < s.Packets.Count; i++)
            {
                BuiltPacket e = s.Packets[i];
                if (i > 0) sb.Append(';');
                sb.Append(e.Kind).Append(':').Append(e.SeqRel.ToString()).Append(':').Append(e.PayloadLen.ToString()).Append(':');
                sb.Append(e.Flags.ToString("x2")).Append(':').Append(e.Ttl.ToString()).Append(':').Append(e.Id.ToString()).Append(':');
                sb.Append(e.ChecksumOk ? "1" : "0").Append(':').Append(Sha256Hex(e.Bytes));
            }
            if (s.Notes.Count > 0) sb.Append("|N:").Append(string.Join(",", s.Notes.ToArray()));
            return sb.ToString();
        }

        public static string DescribePackets(byte[] pkt, string modes, string splitPos, int seqovl, int repeats, string fooling,
            byte[] fakePayload, byte[] pattern, int ttl, int badseqInc, bool ipidZero, bool fakeMod)
        {
            return Describe(Build(pkt, modes, splitPos, seqovl, repeats, fooling, fakePayload, pattern, ttl, badseqInc, ipidZero, fakeMod));
        }

        // A sample IPv4+TCP packet (headers with valid checksums + payload) used for the viewer and tests.
        // timestamps = true adds the TCP Timestamps option (as when TCP timestamps are enabled).
        public static byte[] MakeTemplate(byte[] payload, bool timestamps)
        {
            byte[] opts = new byte[0];
            if (timestamps)
            {
                opts = new byte[] { 1, 1, 8, 10, 0x00, 0xA1, 0xB2, 0xC3, 0x00, 0xD4, 0xE5, 0xF6 };
            }
            byte[] tcp = new byte[20];
            tcp[0] = 0xC8; tcp[1] = 0x22;                       // port 51234
            tcp[2] = 0x01; tcp[3] = 0xBB;                       // port 443
            tcp[4] = 0x1A; tcp[5] = 0x2B; tcp[6] = 0x3C; tcp[7] = 0x4D;
            tcp[8] = 0x5E; tcp[9] = 0x6F; tcp[10] = 0x70; tcp[11] = 0x81;
            tcp[12] = (byte)(((20 + opts.Length) / 4) << 4);
            tcp[13] = 0x18;                                      // PSH + ACK
            tcp[14] = 0x02; tcp[15] = 0x01;                     // window 513
            byte[] ip = new byte[20];
            ip[0] = 0x45;
            int total = 20 + 20 + opts.Length + payload.Length;
            ip[2] = (byte)((total >> 8) & 0xFF);
            ip[3] = (byte)(total & 0xFF);
            ip[4] = 0x1C; ip[5] = 0x46;
            ip[6] = 0x40; ip[7] = 0x00;                         // DF
            ip[8] = 128;
            ip[9] = 6;
            ip[12] = 192; ip[13] = 168; ip[14] = 31; ip[15] = 57;
            ip[16] = 142; ip[17] = 250; ip[18] = 74; ip[19] = 46;
            byte[] seg = Cat(tcp, opts, payload);
            byte[] pseudo = new byte[12 + seg.Length];
            Array.Copy(ip, 12, pseudo, 0, 8);
            pseudo[9] = 6;
            pseudo[10] = (byte)((seg.Length >> 8) & 0xFF);
            pseudo[11] = (byte)(seg.Length & 0xFF);
            Array.Copy(seg, 0, pseudo, 12, seg.Length);
            int cs = Csum16(pseudo);
            seg[16] = (byte)((cs >> 8) & 0xFF);
            seg[17] = (byte)(cs & 0xFF);
            int ics = Csum16(ip);
            ip[10] = (byte)((ics >> 8) & 0xFF);
            ip[11] = (byte)(ics & 0xFF);
            return Cat(ip, seg, new byte[0]);
        }
    }
}
