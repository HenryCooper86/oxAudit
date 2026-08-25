import java.io.File;

class Downloads {
    // Deliberately NOT reported: a caller-supplied name is this helper's API.
    File resolve(String name) {
        return new File("/var/data/" + name);
    }
}
