import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pickle

# For now, we label data using port numbers as ground truth
# Later you can use SNI labels from your C++ output
def label_by_port(row):
    if row['dst_port'] == 443:
        return 'HTTPS'
    elif row['dst_port'] == 80:
        return 'HTTP'
    elif row['dst_port'] == 53:
        return 'DNS'
    elif row['dst_port'] == 3478:
        return 'ZOOM'
    else:
        return 'UNKNOWN'

def train(csv_file="flows.csv"):
    df = pd.read_csv(csv_file)
    df['label'] = df.apply(label_by_port, axis=1)

    features = ['src_port', 'dst_port', 'protocol',
                'packet_count', 'total_bytes', 'min_size', 'max_size']

    X = df[features]
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = RandomForestClassifier(n_estimators=100)
    model.fit(X_train, y_train)

    print(classification_report(y_test, model.predict(X_test)))

    # Save model
    with open("model.pkl", "wb") as f:
        pickle.dump(model, f)

    print("Model saved to model.pkl")

if __name__ == "__main__":
    train()