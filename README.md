# DPI Engine — Deep Packet Inspection System
A network traffic analyzer that inspects packets, classifies applications using TLS/SNI extraction, and predicts traffic types using Machine Learning.

## What It Does
- Reads network capture files (.pcap format)
- Identifies 18+ apps: YouTube, Netflix, Instagram, TikTok, Discord, Spotify, Zoom, and more
- Extracts domain names from encrypted HTTPS traffic (SNI inspection)
- ML model predicts app type from traffic patterns (packet size, ports, flow data)
- REST API built with FastAPI
- Block traffic by app, domain, or IP address

## Tech Stack
- **C++17** — core DPI engine, packet parsing, SNI extraction
- **Python** — feature extraction, ML model, REST API
- **Scapy** — pcap file reading
- **scikit-learn** — Random Forest classifier
- **FastAPI + uvicorn** — REST API backend
- **React** *(coming soon)* — live dashboard

## Project Structure
```
DPI-Engine/
├── cpp/                  # C++ DPI engine
│   ├── src/              # Source files
│   ├── include/          # Header files
│   └── test_dpi.pcap     # Sample capture file
├── python/               # Python ML + API layer
│   ├── pcap_parser.py    # Extracts flow features from pcap
│   ├── ml_model.py       # Trains Random Forest classifier
│   └── api.py            # FastAPI REST API
└── frontend/             # React dashboard (coming soon)
```

## How to Build & Run

### C++ Engine
```bash
g++ -std=c++17 -O2 -I include -o dpi_simple \
    src/main_working.cpp src/pcap_reader.cpp \
    src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp

./dpi_simple input.pcap output.pcap
./dpi_simple input.pcap output.pcap --block-app Netflix
./dpi_simple input.pcap output.pcap --block-domain tiktok --block-ip 192.168.1.50
```

### Python ML + API
```bash
cd python
python3 -m venv venv
source venv/bin/activate
pip install scapy pandas scikit-learn fastapi uvicorn python-multipart

python pcap_parser.py      # Extract features → flows.csv
python ml_model.py         # Train model → model.pkl
uvicorn api:app --reload --port 8000  # Start API
```

API docs available at: `http://localhost:8000/docs`

## API Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Health check |
| POST | `/analyze` | Upload pcap → get ML predictions |
| GET | `/stats` | Usage info |

## Future Plans
- React dashboard with live pie charts and flow table
- Train ML model on real labeled traffic datasets
- Add QUIC/HTTP3 protocol support
- Live packet capture (not just pcap files)
```

After saving, run in WSL:
```bash
git add README.md
git commit -m "Add detailed README"
git push
```
