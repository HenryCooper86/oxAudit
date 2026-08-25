class Employees {
    void find(org.w3c.dom.Document document) throws Exception {
        // The document is a parameter and therefore not constant, but it is
        // not the injection vector — the expression is.
        javax.xml.xpath.XPath xpath = javax.xml.xpath.XPathFactory.newInstance().newXPath();
        String expression = "/Employees/Employee[@id='fixed']";
        xpath.evaluate(expression, document);
    }
}
