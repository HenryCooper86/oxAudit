using System.Text.Json;

class SessionStore {
    public Session Restore(string payload) {
        // The target type is fixed here; nothing in the payload chooses it.
        return JsonSerializer.Deserialize<Session>(payload);
    }
}
