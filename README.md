# droidHunter
NOTE: This project isn't completed. I am willing to resolve the issues you've had and also would love to accept any of your contributions to the project. 
Local toolchain for scanning Android APKs for Firebase exposure. It can:
- Download APKs anonymously via Aurora's token dispenser (Google Play)
- Scan local APKs or a directory of APKs
- Probe Firebase RTDB, Firestore, Storage, and Remote Config endpoints
- Optionally attempt Firebase Auth with extracted API keys

## Project layout
- `backend/` FastAPI API + scan runner
- `web/` Node.js web UI (static assets)
- `aurora-downloader/` Anonymous Google Play downloader CLI
- `data/` Runtime artifacts (APKs, results, job configs)

## Quickstart

### Python API

```bash
cd droidHunter
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.api:app --host 0.0.0.0 --port 8000
```

### Web UI

```bash
cd droidHunter/web
npm install
npm start
```

Open `http://localhost:3000` and set the API base to `http://localhost:8000`.

### One-command start

```bash
./start.sh
```

## Aurora downloader (optional)

Build once:

```bash
./build-aurora.sh
```
This build can also run standalone to download apps by : 
```
./aurora-downloader/build/install/aurora-downloader/bin/aurora-downloader --package foo.bar \
          --output example.apk
```

Requires a local Gradle installation and JDK 21+. Set `JAVA_HOME` (or `AURORA_JAVA_HOME`) to a JDK 21 install.

## Usage notes
- Provide **one** input type per scan (package name, local APK, APK directory, project IDs, DNS file, resume path, or device scan).
- Only scan apps you own or have explicit permission to test.
- Runtime data is stored under `data/`.

## Acknowledgements
- Aurora Store team (AuroraOSS): [GitLab](https://gitlab.com/AuroraOSS/AuroraStore) and [GitHub mirror](https://github.com/whyorean/AuroraStore)
- OpenFirebase contributors: [GitHub](https://github.com/Icex0/OpenFirebase)

## License
MIT. See `LICENSE`. Third-party notices: `THIRD_PARTY_NOTICES.md`.
