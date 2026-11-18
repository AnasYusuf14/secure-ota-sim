# firmware_src

`builds.json` is the human-readable definition of every sample firmware build
used by the demo and the tests. `demo/run_all_scenarios.py` reads it, builds
each image with `common/firmware_image.py` and signs it into `releases/<version>/`.

| Version | Behavior on first boot | Purpose |
|---|---|---|
| 0.9.0 | ok | Old, genuinely signed release (downgrade attack) |
| 1.0.0 | ok | Factory firmware |
| 1.1.0 | ok | Normal update |
| 1.2.0 | fail_selftest | Self-test fails, automatic rollback |
| 1.2.1 | crash | Crashes during boot, automatic rollback |
| 1.3.0 | ok | Fixed release |
