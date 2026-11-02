"""
PhishLens — Flask Application Entry Point & Module Export.
"""

from main import *  # noqa: F401, F403
import main

app = main.app
_results = main._results
_store_lock = main._store_lock

if __name__ == "__main__":
    if not os.path.isfile(config.REPORT_TEMPLATE):
        raise SystemExit(f"Missing report template: {config.REPORT_TEMPLATE}")
    app.run(
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        debug=config.FLASK_DEBUG,
    )

