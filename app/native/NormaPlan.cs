// NORMA desync planner: computes which packets a bypass technique would send for a given TLS ClientHello.
// This is pure computation (no network, no driver), so it can be tested anywhere.
// The same logic exists in tools/engine_ref.py; tests/engine-golden.json holds expected results for both.
// Keep this file ASCII-only and C# 5 compatible: it is compiled by Add-Type in Windows PowerShell 5.1.
using System;
using System.Collections.Generic;
using System.Text;
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
}
