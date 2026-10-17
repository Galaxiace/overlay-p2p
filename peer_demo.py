"""Простой launcher для запуска демонстрации из корня проекта."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from overlay_node.demo import main


if __name__ == "__main__":
    main()
