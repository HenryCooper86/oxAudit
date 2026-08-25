using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

class SessionStore {
    public object Restore(Stream payload) {
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(payload);
    }
}
