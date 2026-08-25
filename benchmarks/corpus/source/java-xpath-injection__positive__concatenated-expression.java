import javax.servlet.http.HttpServletRequest;

class Employees {
    void find(HttpServletRequest request, org.w3c.dom.Document document) throws Exception {
        javax.xml.xpath.XPath xpath = javax.xml.xpath.XPathFactory.newInstance().newXPath();
        String expression = "/Employees/Employee[@id='" + request.getParameter("id") + "']";
        xpath.evaluate(expression, document);
    }
}
