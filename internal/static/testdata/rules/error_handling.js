app.get('/a', (req, res) => {
  try { work(); } catch (err) {
    // ruleid: sift.error-stack-trace-leak
    res.status(500).json({ error: err.message });
    // ruleid: sift.error-stack-trace-leak
    res.send(err);
    // ok: sift.error-stack-trace-leak
    res.status(404).json({ error: 'Not found' });
  }
});

// ruleid: sift.error-unhandled-rejection
process.on('unhandledRejection', () => {});
// ok: sift.error-unhandled-rejection
process.on('unhandledRejection', (reason) => { console.error(reason); process.exit(1); });
// ok: sift.error-unhandled-rejection
process.on('SIGTERM', () => server.close());
