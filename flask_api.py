from flask import Flask, request, jsonify
import joblib
import numpy as np
import os

# ✅ Load the trained model
model = joblib.load("cybersecurity_model.pkl")

app = Flask(__name__)

# ✅ Route for the root path
@app.route('/')
def home():
    return "✅ AI-Powered Cybersecurity Threat Detection is live and running!"

# ✅ Route for making predictions
@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    features = np.array([[data.get("protocol", 0),
                          data.get("flow_duration", 0),
                          data.get("total_forward_packets", 0),
                          data.get("total_backward_packets", 0),
                          data.get("total_forward_packets_length", 0),
                          data.get("total_backward_packets_length", 0),
                          data.get("forward_packet_length_mean", 0),
                          data.get("backward_packet_length_mean", 0),
                          data.get("forward_packets_per_second", 0),
                          data.get("backward_packets_per_second", 0),
                          data.get("forward_iat_mean", 0),
                          data.get("backward_iat_mean", 0),
                          data.get("flow_iat_mean", 0),
                          data.get("flow_packets_per_seconds", 0),
                          data.get("flow_bytes_per_seconds", 0)]])
    prediction = model.predict(features)
    return jsonify({"Threat_Detected": bool(prediction[0])})


# ✅ Run app in the right way for Render
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
