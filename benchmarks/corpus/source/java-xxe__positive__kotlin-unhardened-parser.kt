import javax.xml.parsers.DocumentBuilderFactory
import java.io.InputStream

class Importer {
    fun parse(input: InputStream) {
        val factory = DocumentBuilderFactory.newInstance()
        factory.newDocumentBuilder().parse(input)
    }
}
