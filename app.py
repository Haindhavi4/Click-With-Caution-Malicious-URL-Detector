from flask import Flask, request, render_template, jsonify
from featureExtractor import featureExtraction
from pycaret.classification import load_model, predict_model
import pandas as pd

app = Flask(__name__)
model = load_model('model/phishingdetection')

# Store previous checks (this can be replaced with a database later)
previous_checks = []

def predict(url):
    data = pd.DataFrame([featureExtraction(url)])  # Convert to DataFrame
    result = predict_model(model, data=data)
    prediction_score = result['prediction_score'][0]  
    prediction_label = result['prediction_label'][0]  
    return {
        'prediction_label': prediction_label,
        'prediction_score': prediction_score * 100,
    }

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        prediction = predict(url)
        previous_checks.append({'url': url, 'result': prediction})
        return jsonify(prediction)
    return render_template("index.html", previous_checks=previous_checks)

if __name__ == "__main__":  # Fixed typo
    app.run(debug=True)
