import javax.xml.parsers.DocumentBuilderFactory
import java.io.InputStream

class Importer {
    fun parse(input: InputStream) {
        val factory = DocumentBuilderFactory.newInstance()
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        factory.newDocumentBuilder().parse(input)
    }
}
