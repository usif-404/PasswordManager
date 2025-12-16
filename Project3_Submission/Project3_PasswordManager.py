from __future__ import annotations
from dataclasses import dataclass
from abc import ABC, abstractmethod
import time
import os
from typing import List, Optional, Tuple

# Optional (Part 3 plot)
_MPL_ERR = None
try:
    import matplotlib
    matplotlib.use("Agg")  # render to file; no GUI backend needed
    import matplotlib.pyplot as plt
except Exception as e:
    plt = None
    _MPL_ERR = e

def _time_ms(fn, repeats: int = 1) -> float:
    t0 = time.perf_counter()
    for _ in range(max(1, int(repeats))):
        fn()
    return round((time.perf_counter() - t0) * 1000.0, 3)

# =========================
# Part 2: OOP (Abstraction + Inheritance)
# =========================
class RecordBase(ABC):
    @property
    @abstractmethod
    def key(self) -> str:
        pass

    @abstractmethod
    def serialize(self) -> str:
        pass


def _escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "\\n").replace("\r", "\\r")


def _unescape(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt == "n":
                out.append("\n"); i += 2; continue
            if nxt == "r":
                out.append("\r"); i += 2; continue
            if nxt == "|":
                out.append("|"); i += 2; continue
            if nxt == "\\":
                out.append("\\"); i += 2; continue
        out.append(s[i])
        i += 1
    return "".join(out)


def _split_escaped(line: str, sep: str = "|") -> List[str]:
    parts = []
    buf = []
    escape = False
    for ch in line:
        if escape:
            buf.append(ch)
            escape = False
            continue
        if ch == "\\":
            buf.append(ch)
            escape = True
            continue
        if ch == sep:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return parts


@dataclass
class PasswordEntry(RecordBase):
    site: str
    username: str
    password: str

    @property
    def key(self) -> str:
        return self.site

    def serialize(self) -> str:
        return f"{_escape(self.site)}|{_escape(self.username)}|{_escape(self.password)}"

    @staticmethod
    def deserialize(line: str) -> "PasswordEntry":
        parts = _split_escaped(line, "|")
        if len(parts) < 3:
            raise ValueError("Corrupted entry line.")
        return PasswordEntry(
            site=_unescape(parts[0]),
            username=_unescape(parts[1]),
            password=_unescape(parts[2]),
        )



# Alias to match spec naming (User, Password, Vault)
Password = PasswordEntry

@dataclass
class User:
    username: str
    xor_key: int  # 0..255


# =========================
# Part 1: File Processing + XOR
# =========================
def xor_bytes(data: bytes, key: int) -> bytes:
    k = key & 0xFF
    return bytes((b ^ k) for b in data)


class Vault:
    def __init__(self) -> None:
        self._entries: List[PasswordEntry] = []
        self._sorted_cache: List[PasswordEntry] | None = None
        self._dirty_sorted = True

    @property
    def entries(self) -> List[PasswordEntry]:
        return self._entries

    def _mark_dirty(self) -> None:
        self._dirty_sorted = True
        self._sorted_cache = None

    def add(self, e: PasswordEntry) -> None:
        self._validate(e)
        self._entries.append(e)
        self._mark_dirty()

    def update(self, site: str, updated: PasswordEntry) -> bool:
        self._validate(updated)
        for i, e in enumerate(self._entries):
            if e.site.lower() == site.lower():
                self._entries[i] = updated
                self._mark_dirty()
                return True
        return False

    def delete(self, site: str) -> bool:
        for i, e in enumerate(self._entries):
            if e.site.lower() == site.lower():
                del self._entries[i]
                self._mark_dirty()
                return True
        return False

    def find_linear(self, site: str) -> Optional[PasswordEntry]:
        target = site.lower()
        for e in self._entries:
            if e.site.lower() == target:
                return e
        return None

    def _ensure_sorted(self) -> List[PasswordEntry]:
        if self._dirty_sorted or self._sorted_cache is None:
            self._sorted_cache = sorted(self._entries, key=lambda x: x.site.lower())
            self._dirty_sorted = False
        return self._sorted_cache

    def find_binary(self, site: str) -> Optional[PasswordEntry]:
        arr = self._ensure_sorted()
        lo, hi = 0, len(arr) - 1
        target = site.lower()
        while lo <= hi:
            mid = (lo + hi) // 2
            mid_site = arr[mid].site.lower()
            if mid_site == target:
                return arr[mid]
            if mid_site < target:
                lo = mid + 1
            else:
                hi = mid - 1
        return None

    def load_from_file(self, path: str, xor_key: int) -> None:
        self._entries.clear()
        self._mark_dirty()
        if not os.path.exists(path):
            return

        with open(path, "rb") as f:
            enc = f.read()

        dec = xor_bytes(enc, xor_key)

        try:
            text = dec.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise ValueError("Wrong XOR key (cannot decode vault).")

        lines = [ln for ln in text.splitlines() if ln.strip()]
        for ln in lines:
            self._entries.append(PasswordEntry.deserialize(ln))
        self._mark_dirty()

    def save_to_file(self, path: str, xor_key: int) -> None:
        # Backup قبل ما نحفظ
        if os.path.exists(path):
            bak = path + ".bak"
            try:
                with open(path, "rb") as fsrc, open(bak, "wb") as fdst:
                    fdst.write(fsrc.read())
            except Exception:
                pass

        text = "\n".join(e.serialize() for e in self._entries)
        plain = text.encode("utf-8")
        enc = xor_bytes(plain, xor_key)

        with open(path, "wb") as f:
            f.write(enc)

    @staticmethod
    def _validate(e: PasswordEntry) -> None:
        if not e.site.strip():
            raise ValueError("Site cannot be empty.")
        if not e.username.strip():
            raise ValueError("Username cannot be empty.")
        if not e.password:
            raise ValueError("Password cannot be empty.")


# =========================
# Part 3: Performance Analysis
# =========================
def perf_run() -> None:
    print("\n=== Part 3: Performance Analysis (Linear vs Binary) ===")
    sizes = [1000, 5000, 10000, 20000]
    results: List[Tuple[int, float, float]] = []

    for n in sizes:
        v = Vault()
        for i in range(n):
            v.add(PasswordEntry(site=f"site{i}.com", username=f"user{i}", password=f"pass{i}"))

        target = f"site{n-1}.com"
        v._ensure_sorted()  # build cache once (so timing is search-only)

        linear_ms = _time_ms(lambda: v.find_linear(target), repeats=200)
        binary_ms = _time_ms(lambda: v.find_binary(target), repeats=200)
        results.append((n, linear_ms, binary_ms))
        print(f"N={n:<6}  Linear={linear_ms:>6} ms   Binary={binary_ms:>6} ms (200 repeats)")

    if plt:
        xs = [r[0] for r in results]
        y1 = [r[1] for r in results]
        y2 = [r[2] for r in results]
        plt.figure()
        plt.plot(xs, y1, marker="o", label="Linear")
        plt.plot(xs, y2, marker="o", label="Binary")
        plt.xlabel("N (number of entries)")
        plt.ylabel("Time (ms) for 200 searches")
        plt.title("Linear vs Binary Search Performance")
        plt.grid(True, linestyle="--", linewidth=0.5)
        plt.legend()
        plt.tight_layout()
        try:
            plt.savefig("perf_plot.png", dpi=200)
            print("Saved plot: perf_plot.png")
        except Exception:
            pass
    else:
        print(f"Plot skipped (matplotlib import failed: {_MPL_ERR})")


def login() -> User:
    username = input("Enter username: ").strip() or "user"
    while True:
        s = input("Enter XOR numeric key (0-255): ").strip()
        try:
            key = int(s)
            if 0 <= key <= 255:
                return User(username=username, xor_key=key)
        except ValueError:
            pass
        print("Invalid key. Must be 0..255.")


def _print_entry(e: Optional[PasswordEntry]) -> None:
    if e is None:
        print("Not found ❌")
    else:
        print(f"Found ✅  Site: {e.site}")
        print(f"Username: {e.username}")
        print(f"Password: {e.password}")



def _safe_username(name: str) -> str:
    # Keep filename-friendly characters only
    s = "".join(ch if (ch.isalnum() or ch in "._-") else "_" for ch in (name or "user"))
    s = s.strip("._-") or "user"
    return s

def _open_user_vault(base_dir: str, user: User, vault: Vault) -> Tuple[str, bool]:
    """
    Returns (file_path, loaded_ok)
    """
    safe_user = _safe_username(user.username)
    file_path = os.path.join(base_dir, f"vault_{safe_user}.dat")
    print("Vault path:", file_path)

    try:
        vault.load_from_file(file_path, user.xor_key)
        print(f"Loaded {len(vault.entries)} entries for user '{user.username}'.\n")
        return file_path, True
    except Exception as ex:
        print(f"Failed to load vault for '{user.username}': {ex}")
        print("Tip: Key غلط => مش هتشوف الداتا. وما تعملش Save إلا لو متأكد.\n")
        return file_path, False


# =========================
# Main
# =========================
def main() -> None:
    print("=== Password Manager (XOR Encrypted Vault) ===")

    base_dir = os.path.dirname(os.path.abspath(__file__))

    vault = Vault()
    current_user = login()
    file_path, loaded_ok = _open_user_vault(base_dir, current_user, vault)

    dirty = False  # تغييرات غير محفوظة

    while True:
        print(f"\n[Current User: {current_user.username}]  Unsaved changes: {'YES' if dirty else 'NO'}")
        print("1) Add password")
        print("2) Retrieve password (Linear)")
        print("3) Retrieve password (Binary)")
        print("4) Update password")
        print("5) Delete password")
        print("6) List sites")
        print("7) Save")
        print("8) Run Performance Analysis (Part 3)")
        print("9) Switch User (open another user's vault)")
        print("0) Exit (NO auto-save)")
        ch = input("Choose: ").strip()

        try:
            if ch == "1":
                site = input("Site: ").strip()
                uname = input("Username: ").strip()
                pwd = input("Password: ")
                vault.add(PasswordEntry(site=site, username=uname, password=pwd))
                dirty = True
                print("Added ✅")

            elif ch == "2":
                site = input("Enter site to search: ").strip()
                _print_entry(vault.find_linear(site))

            elif ch == "3":
                site = input("Enter site to search: ").strip()
                _print_entry(vault.find_binary(site))

            elif ch == "4":
                old = input("Enter site to update: ").strip()
                site = input("New Site: ").strip()
                uname = input("New Username: ").strip()
                pwd = input("New Password: ")
                ok = vault.update(old, PasswordEntry(site=site, username=uname, password=pwd))
                if ok:
                    dirty = True
                print("Updated ✅" if ok else "Site not found ❌")

            elif ch == "5":
                site = input("Enter site to delete: ").strip()
                ok = vault.delete(site)
                if ok:
                    dirty = True
                print("Deleted ✅" if ok else "Site not found ❌")

            elif ch == "6":
                if not vault.entries:
                    print("(Empty)")
                else:
                    print("Sites:")
                    for s in sorted((e.site for e in vault.entries), key=lambda x: x.lower()):
                        print("-", s)

            elif ch == "7":
                vault.save_to_file(file_path, current_user.xor_key)
                dirty = False
                print(f"Saved ✅ (backup: {os.path.basename(file_path)}.bak)")

            elif ch == "8":
                perf_run()

            elif ch == "9":
                if dirty:
                    ans = input("You have UNSAVED changes. Save now? (y/n): ").strip().lower()
                    if ans == "y":
                        vault.save_to_file(file_path, current_user.xor_key)
                        dirty = False
                        print("Saved ✅")

                # switch
                print("\n--- Switch User ---")
                new_user = login()
                current_user = new_user
                file_path, loaded_ok = _open_user_vault(base_dir, current_user, vault)
                dirty = False

            elif ch == "0":
                print("Bye 👋")
                return

            else:
                print("Invalid choice.")
        except Exception as ex:
            print(f"Error: {ex}")


if __name__ == "__main__":
    main()
