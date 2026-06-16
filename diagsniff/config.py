from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from .models import DeviceProfile, ProfileStore
from .platform_utils import get_app_dir

log = logging.getLogger(__name__)

_PROFILES_FILE = "profiles.json"


class ProfileManager:
    def __init__(self) -> None:
        self._path: Path = get_app_dir() / _PROFILES_FILE

    def _load_store(self) -> ProfileStore:
        if not self._path.exists():
            return ProfileStore()
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            return ProfileStore.model_validate(raw)
        except Exception as exc:
            log.warning("Could not parse profiles file: %s. Starting fresh.", exc)
            return ProfileStore()

    def _save_store(self, store: ProfileStore) -> None:
        self._path.write_text(
            store.model_dump_json(indent=2),
            encoding="utf-8",
        )

    # ── Public CRUD ───────────────────────────────────────────────────────────

    def save(self, profile: DeviceProfile) -> None:
        store = self._load_store()
        store.profiles[profile.name] = profile
        self._save_store(store)
        log.debug("Profile saved: %s", profile.name)

    def get(self, name: str) -> Optional[DeviceProfile]:
        return self._load_store().profiles.get(name)

    def list_all(self) -> list[DeviceProfile]:
        return list(self._load_store().profiles.values())

    def delete(self, name: str) -> bool:
        store = self._load_store()
        if name not in store.profiles:
            return False
        del store.profiles[name]
        self._save_store(store)
        return True

    def exists(self, name: str) -> bool:
        return name in self._load_store().profiles


# Module-level singleton — import and use directly
profile_manager = ProfileManager()
