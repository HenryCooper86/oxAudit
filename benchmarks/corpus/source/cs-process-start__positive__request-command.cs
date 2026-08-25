using System.Diagnostics;

class Converter {
    public void Run(string userInput) {
        Process.Start("cmd.exe", userInput);
    }
}
