import javax.xml.parsers.DocumentBuilderFactory;

class Importer {
    void parse(java.io.InputStream input) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Entity resolution is switched off before the document is read.
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setExpandEntityReferences(false);
        factory.newDocumentBuilder().parse(input);
    }
}
