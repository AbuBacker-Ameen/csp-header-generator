# Roadmap for HashCSP

## **Planned Features**

### 🔹 CSP Generation Enhancements

- [ ] Add `MutationObserver` injection to capture dynamically inserted
      `<script>` and `<style>` tags.
- [ ] Enable smart dynamic waiting: adapt session length based on live DOM
      mutations, not just fixed sleep.
- [ ] Traverse Shadow DOM trees during DOM snapshotting to detect hidden
      resources.
- [ ] Improve hashing of late-loaded scripts and styles from dynamically
      modified DOM.

### 🔹 CLI Improvements

- [ ] Add `--observe-dom` flag to enable/disable dynamic mutation tracking.
- [ ] Improve `--deep-wait` logic to include dynamic idle detection.
- [ ] Add `--scan-depth` or `--crawl-links` feature to allow scanning multiple
      linked pages (future deep audit mode).
- [ ] Implement a `--mode [fast|deep|audit]` system for user-friendly scan level
      control.

### 🔹 Reliability and UX

- [ ] Add real-time progress indicators or countdown during deep scans.
- [ ] Improve error reporting with clearer distinction between fetch/network/DOM
      parse failures.
- [ ] Include optional `verbose` and `silent` modes for CLI output control.

### 🔹 Security Hardening

- [ ] Offer static nonce generation option (with very clear documentation on
      limitations).
- [ ] Support CSP violation reporting endpoint configuration.

### 🔹 Documentation

- [ ] Expand examples for each scan mode.
- [ ] Write a full explanation of how dynamic JavaScript affects CSP generation.
- [ ] Publish a comparison of hash-based CSP vs nonce-based CSP policies.

---

## **Future Long-Term Ideas**

- [ ] Create Flask/Django middleware to generate CSP on-the-fly using HashCSP
      core engine.
- [ ] Build a minimal web UI dashboard for CSP report visualization.
- [ ] Publish HashCSP on PyPI for easier installation (`pip install hashcsp`).
