# owctl Improvements & Plan of Attack

## Current State
- 1,229 Py + 715 HTML = 1,944 lines
- 6 tabs, 128K DB, 33/33 tests pass
- 2 devices, ~15 features complete

---

## Improvements List

### UI/UX (Priority: High→Low)
| # | Feature | Est. Lines | Notes |
|---|---------|------------|-------|
| 1 | Theme toggle (dark/light) | ~50 | CSS variables swap |
| 2 | Device search/filter bar | ~30 | JS filter on table |
| 3 | Real-time polling (60s auto-refresh) | ~40 | setInterval + conditional render |
| 4 | Sortable device table | ~20 | JS sort on column click |
| 5 | Collapsible device sections | ~25 | CSS toggle |
| 6 | Mobile responsive tweaks | ~30 | Media queries |
| 7 | Keyboard shortcuts | ~15 | keydown listener |

### Features
| # | Feature | Est. Lines | Notes |
|---|---------|------------|-------|
| 8 | Health trend chart | ~80 | Canvas/line chart, need history endpoint |
| 9 | Bandwidth calc (Mbps) | ~40 | Delta between samples / time diff |
| 10 | Export as JSON/CSV | ~30 | Blob download |
| 11 | Config diff highlights | ~50 | Side-by-side with color coding |
| 12 | Scheduled audits setting | ~60 | UI + backend cron flag |
| 13 | Alert notification sound | ~20 | Audio element |

### Security
| # | Feature | Est. Lines | Notes |
|---|---------|------------|-------|
| 14 | Token required by default | ~10 | Change default setting |
| 15 | Bind localhost by default | ~5 | Change uvicorn host |
| 16 | Hash passwords (bcrypt) | ~30 | Upgrade path needed |

### Reliability
| # | Feature | Est. Lines | Notes |
|---|---------|------------|-------|
| 17 | Auto DB backup | ~20 | Cron/shutil.copy |
| 18 | Health endpoint (/health) | ~10 | Simple ping |

### Stretch (low priority)
| # | Feature | Est. Lines |
|---|---------|------------|
| 19 | WireGuard peer management | ~150 |
| 20 | Firewall rule editor | ~100 |
| 21 | DHCP lease management | ~60 |
| 22 | Device templates | ~40 |

---

## Plan of Attack

### Phase 4 — Quick Wins (Day 1, ~3h)
**Items: 1, 2, 3, 14, 9**

Rationale: These require minimal code changes and provide immediate UX value.
- Theme toggle: CSS variables already exist, just add light class
- Search/filter: Pure JS on existing device list
- Polling: One setInterval in renderDevices()
- Token default: One config change
- Bandwidth: Calculate delta from traffic_samples endpoint

### Phase 5 — Useful Features (Day 2, ~4h)
**Items: 8, 11, 10, 12, 15**

Rationale: Moderate complexity, high utility.
- Health trend: Need new endpoint + canvas chart
- Config diff: Visual highlight of changed files
- Export: Simple JSON/CSV serialization
- Scheduled audits: UI for interval setting + scheduler hook
- Localhost bind: Startup config change

### Phase 6 — Polish (Day 3, ~3h)
**Items: 4, 5, 6, 7, 17**

Rationale: Fine-tuning and reliability.
- Sortable table: Column header click handlers
- Collapsible sections: CSS toggle
- Mobile responsive: Media queries
- Keyboard shortcuts: Global keydown listener
- DB backup: Scheduled copy job

### Phase 7 — Stretch (as needed)
**Items: 13, 16, 18-22**

Deferred to later sessions based on usage patterns.

---

**Total estimated:** ~600 lines across phases 4-6
**Skipped:** WireGuard, multi-tenancy, RADIUS (out of scope for owctl)
