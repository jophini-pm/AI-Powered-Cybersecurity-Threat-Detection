
from flask import Flask, request, jsonify
import joblib
import numpy as np

# Load the trained model
model = joblib.load("cybersecurity_model.pkl")

# Initialize Flask app
app = Flask(__name__)

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get JSON request data
        data = request.get_json()
        
        # Extract features
        features = np.array([[
            data["protocol"],
            data["flow_duration"],
            data["total_forward_packets"],
            data["total_backward_packets"],
            data["total_forward_packets_length"],
            data["total_backward_packets_length"],
            data["forward_packet_length_mean"],
            data["backward_packet_length_mean"],
            data["forward_packets_per_second"],
            data["backward_packets_per_second"],
            data["forward_iat_mean"],
            data["backward_iat_mean"],
            data["flow_iat_mean"],
            data["flow_packets_per_seconds"],
            data["flow_bytes_per_seconds"]
        ]])

        # Make prediction
        prediction = model.predict(features)
        
        return jsonify({"Threat_Detected": bool(prediction[0])})
    
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
