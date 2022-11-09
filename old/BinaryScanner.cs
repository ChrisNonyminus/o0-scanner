using System.Net.Mime;
using System.Text;
using System.ComponentModel;
using System.Text.RegularExpressions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Eocron;

namespace o0_scanner
{
    public static class BinaryScanner
    {
        public static ORegex<byte> REIDOJumpNop = 
        new ORegex<byte>("{0}{3,3}{1}{2}{4,4}{3}{3,3}{4}{5}{4,4}{6}{3,3}{7}{8}{4,4}", x => true, x=> x == 0x08, x=> x == 0,  x => true, x=> x == 0x08, x=> x == 0,  x => true, x=> x == 0x08, x=> x == 0);
        //@"[\s\S][\s\S][\s\S]\x08\x00\x00\x00\x00";
        public static ORegex<byte> REWatcomStackEpilog = 
        new ORegex<byte>("{0}{1}{2}{3}{4}{5}{6}", 0x5f, 0x5e, 0x5a, 0x59, 0x5b, 0x5d, 0xc3);
        //@"\x5F\x5E\x5A\x59\x5B\x5D\xC3";
        public static ORegex<byte> REMSVC6Stack = 
        new ORegex<byte>("{0}{1}{2}{3}*{4}{5}", x=> x == 0x55, x => x== 0x89 || x == 0x8b, x => x== 0xec, x=> x != 0xc3 && x != 0xc2, x =>x == 0x5d, x =>x == 0xc3 || x == 0xc2);
        //@"\x55[\s\S][\s\S]\x29\x25[\s\S][\s\S][\s\S][\s\S]\x8b[\s\S][\s\S]\x89[\s\S][\s\S]";
        public static ORegex<byte> REAGBCCPotentialO0Prolog = 
        new ORegex<byte>("{0}{1}{2}{3}", 0x80, 0xb5, 0x6f, 0x46);



        public static int Search (this byte[] self, ORegex<byte> regex)
        {
            return regex.Matches(self).Count;
        }


    }
}