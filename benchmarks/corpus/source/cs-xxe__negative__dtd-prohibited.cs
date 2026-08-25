using System.Xml;

class Importer {
    public XmlReader Open(string path) {
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Prohibit;
        settings.XmlResolver = null;
        return XmlReader.Create(path, settings);
    }
}
