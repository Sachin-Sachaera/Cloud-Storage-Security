# Upload pipeline progress

- [ ] Inspect current upload + scan verdict logic
- [x] Add safe-override rule for genuine PDFs (detected_signature == 'pdf') to prevent clean PDFs from being blocked when ML misclassifies

- [ ] Re-run app (optional) and verify upload of clean PDF goes to SAFE and is stored
- [ ] Verify suspicious PDFs are still stored (not blocked) and show reasons

