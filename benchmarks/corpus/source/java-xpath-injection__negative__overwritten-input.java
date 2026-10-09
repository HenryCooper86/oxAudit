class LocalPath {
    void run(javax.xml.xpath.XPath xpath, String input, org.w3c.dom.Document document) throws Exception {
        String expression = input;
        expression = "/people/person";
        xpath.evaluate(expression, document);
    }
}
