from flask import Flask, render_template, request
import pickle
import pandas as pd
from preprocessing_url import *

app = Flask(__name__)

# Load the model from the saved file
with open('dtc.pkl', 'rb') as model:
    prediction_model = pickle.load(model)


# Define feature list
feature_list = ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//']

def preprocess_url(url):
    features = {
        'url_len': get_url_length(url),
        'use_of_ip':having_ip_address(url),
        'count_https':count_https(url),
        'count_http':count_http(url),
        'abnormal_url':abnormal_url(url),
        'sum_count_special_chars':sum_count_special_characters(url),
        'redirection':redirection(url),
        'short_url':shortening_service(url),
        'count_digits':digit_count(url),
        'hostname_length':hostname_length(url),
        'tld_length':get_tld_length(url),
        'fd_len':fd_length(url),
        'is_sus_words':suspicious_words(url),
    }
    counts = calculate_count(url, feature_list)
    features.update(counts)  # Add character counts to the features
    df_features = pd.DataFrame([features])

    # Reorder columns to match the model's expected feature order
    expected_order = [
        'url_len', 'use_of_ip', 'count_https', 'count_http', 'abnormal_url', 
        '@', '?', '-', '=', '.','#', '%', '+', '$', '!', '*', ',', '//', 
        'sum_count_special_chars', 'redirection', 'short_url', 'count_digits' , 
        'hostname_length', 'tld_length','fd_len', 'is_sus_words'
    ]
    df_features = df_features[expected_order]
    return df_features


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        url = request.form['url']  # Get URL input from user
        preprocessed_url_df = preprocess_url(url)  # Preprocess the input URL

        # Predict using the Decision Tree classifier
        prediction = prediction_model.predict(preprocessed_url_df)
        prediction_proba = prediction_model.predict_proba(preprocessed_url_df)  # Get probability
        
        # Class mapping (depends on your label encoding)
        class_mapping = {
            0: 'Benign',
            1: 'Defacement',
            2: 'Malware',
            3: 'Phishing'
        }

        # Get the class label and confidence
        predicted_class = class_mapping[prediction[0]]
        confidence_score = prediction_proba[0][prediction[0]] * 100  # Convert to percentage
        
        # Check if the prediction is malicious
        is_malicious = predicted_class != 'Benign'

        return render_template('index.html', prediction=predicted_class, confidence=confidence_score, is_malicious=is_malicious)


if __name__ == '__main__':
    app.run(debug=True)

