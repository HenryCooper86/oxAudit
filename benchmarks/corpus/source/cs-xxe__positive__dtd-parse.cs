using System.Xml;

class Importer {
    public XmlReader Open(string path) {
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse;
        return XmlReader.Create(path, settings);
    }
}
