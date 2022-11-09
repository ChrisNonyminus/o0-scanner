using System.ComponentModel;
using System.Text.RegularExpressions;
using CommandLine;
using o0_scanner;

var options = Parser.Default.ParseArguments<Options>(args).Value;

var files = Directory.GetFiles(options.ScanDir ?? ".");

if (options.BinaryType == "n64-ido")
{
    files = files.Where(x => x.EndsWith(".n64") || x.EndsWith(".ndd")).ToArray();
}
if (options.BinaryType == "watcom-le" || options.BinaryType == "win32-msvc")
    files = files.Where(x => x.ToUpper().EndsWith(".EXE")).ToArray();

if (options.BinaryType == "gba")
    files = files.Where(x => x.EndsWith(".gba")).ToArray();

List<string> results = new List<string>();
foreach (var file in files)
{
    byte[] bytes = File.ReadAllBytes(file);
    int numPatternMatches = 0;
    switch (options.BinaryType)
    {
        case "n64-ido": 
        numPatternMatches = bytes.Search(BinaryScanner.REIDOJumpNop); 
    results.Add($"{file} had {numPatternMatches} hits when searching for jump instructions followed by nops."); break;
        case "watcom-le": 
        numPatternMatches = bytes.Search(BinaryScanner.REWatcomStackEpilog); 
    results.Add($"{file} had {numPatternMatches} hits when searching for \"chunky\" stack popping epilogs."); break;
        case "win32-msvc": 
        numPatternMatches = bytes.Search(BinaryScanner.REMSVC6Stack); 
    results.Add($"{file} had {numPatternMatches} hits when searching for what seems like stack shenanigans?"); break;
        case "gba":
        numPatternMatches = bytes.Search(BinaryScanner.REAGBCCPotentialO0Prolog); 
    results.Add($"{file} had {numPatternMatches} hits when searching for what seems like stack shenanigans?"); break;
        default: break;
    }
}

results.Sort( delegate (string x, string y){
    int numx = Int32.Parse(Regex.Match(x, @"had (?<num>.*) hits").Groups["num"].Value);
    int numy = Int32.Parse(Regex.Match(y, @"had (?<num>.*) hits").Groups["num"].Value);
    return numx.CompareTo(numy);
});

results.ForEach(x => Console.WriteLine(x));

Console.WriteLine("Done!");

public class Options
{
    [Option('i', "directory", Required = true, HelpText = "Directory of binary files to scan in.")]
    public string ?ScanDir {get; set;}
    [Option('t', "type", Required = true, HelpText = "Type of binary file to scan.\n\tSupported files: \"n64-ido\" (N64 roms built with IDO), \"watcom-le\" (DOS 32 bit executables built with Watcom), \"win32-msvc\" (win32 PEs built with MSVC6), \"gba\" (self explanatory).")]
    public string? BinaryType {get; set;}
}