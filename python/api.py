from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import pickle, shutil, os
from pcap_parser import extract_features

app = FastAPI()

# Allow React frontend to talk to this
app.add_middleware(CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Load ML model
with open("model.pkl", "rb") as f:
    model = pickle.load(f)

@app.get("/")
def root():
    return {"status": "DPI Engine API running"}
@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    # Save uploaded pcap
    with open("uploaded.pcap", "wb") as f:
        shutil.copyfileobj(file.file, f)

    # Extract features
    df = extract_features("uploaded.pcap")

    features = ['src_port', 'dst_port', 'protocol',
                'packet_count', 'total_bytes', 'min_size', 'max_size']

    predictions = model.predict(df[features])
    df['predicted_app'] = predictions

    # Summary
    summary = df['predicted_app'].value_counts().to_dict()

    return {
        "total_flows": len(df),
        "app_breakdown": summary,
        "flows": df.to_dict(orient="records")
    }

@app.get("/stats")
def stats():
    return {"message": "Upload a pcap file to /analyze"}
