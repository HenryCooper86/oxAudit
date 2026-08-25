import java.io.File;

class Config {
    File resolve() {
        return new File("/etc/oxaudit/config.json");
    }
}
