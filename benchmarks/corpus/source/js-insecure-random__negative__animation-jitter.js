function stagger(index) {
  // Nothing here needs to be unguessable.
  const jitter = Math.random() * 50;
  return index * 100 + jitter;
}
