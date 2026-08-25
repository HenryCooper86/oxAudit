import javax.xml.parsers.DocumentBuilderFactory;

class Catalog {
    void parse(java.io.InputStream input) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // The only evidence of the fix lives inside a quoted feature URI.
        // The sibling fixture also calls setExpandEntityReferences(false),
        // so it passed on that alternative while this form stayed unfirable.
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.newDocumentBuilder().parse(input);
    }
}
