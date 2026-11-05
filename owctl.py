"""owctl entrypoint shim.

The real backend is the ``owctl`` package (this directory). Kept so ``python owctl.py`` and the
systemd/launchd units keep working. ``import owctl`` resolves to the package (packages take
precedence over same-named files), so all ``owctl.<name>`` references and test monkeypatches stay stable.
"""
import owctl

if __name__ == "__main__":
    owctl.main()
