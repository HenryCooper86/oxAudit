class Sessions {
    public string NewSessionToken() {
        var random = new Random();
        return random.Next().ToString("x8");
    }
}
