function createSession(user) {
  const sessionToken = Math.random().toString(36).slice(2);
  return { user, sessionToken };
}
