import javax.xml.parsers.DocumentBuilderFactory;

class Importer {
    void parse(java.io.InputStream input) throws Exception {
        // Default configuration resolves external entities, so a crafted
        // document can read local files or reach internal services.
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.newDocumentBuilder().parse(input);
    }
}
