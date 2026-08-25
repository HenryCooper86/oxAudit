using System.Diagnostics;

class Converter {
    public void Run(string userInput) {
        // ArgumentList is passed to the OS as argv; no shell parses it.
        var info = new ProcessStartInfo("convert") { UseShellExecute = false };
        info.ArgumentList.Add(userInput);
        Process.Start(info);
    }
}
