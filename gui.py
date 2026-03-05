import tkinter as tk
import pickle
import re
import numpy as np
from scipy.sparse import hstack
from counter import increment_attack  # your existing attack counter

# -------- Load saved model and TF-IDF --------
tfidf = pickle.load(open("ml version/tfidf_vectorizer.pkl", "rb"))
xgb_model = pickle.load(open("ml version/sql_rf_model.pkl", "rb"))

# -------- Helper function to clean query --------
def clean_query(query):
    query = query.lower()
    query = re.sub(r'--.*', '', query)          # remove comments
    query = re.sub(r'/\*.*?\*/', '', query, flags=re.DOTALL)
    query = re.sub(r'\s+', ' ', query)         # normalize whitespace
    return query.strip()

# -------- Extract extra numeric features --------
def extract_features(query):
    and_count = query.count('and')
    or_count = query.count('or')
    union_count = query.count('union')
    single_quote_count = query.count("'")
    double_quote_count = query.count('"')
    constant_value_count = len(re.findall(r'\b\d+\b', query))
    parentheses_count = query.count('(') + query.count(')')
    special_char_total = len(re.findall(r'[;=#\-]', query))

    return np.array([[and_count, or_count, union_count,
                      single_quote_count, double_quote_count,
                      constant_value_count, parentheses_count, special_char_total]])

# -------- Predict Function with Confidence --------
def predict_query(query):
    query_clean = clean_query(query)
    X_text = tfidf.transform([query_clean])
    X_extra = extract_features(query_clean)
    X_final = hstack([X_text, X_extra])

    pred = xgb_model.predict(X_final)[0]
    proba = xgb_model.predict_proba(X_final)[0]  # [prob_normal, prob_injection]
    confidence = proba[pred] * 100  # as percentage

    return ("Normal" if pred == 0 else "SQL Injection", confidence)

# -------- GUI --------
def start_gui():

    def gui_detect():
        query = entry.get().strip()
        query = re.sub(r'\s+', ' ', query)  # normalize whitespace

        pred, confidence = predict_query(query)

        if pred == "SQL Injection":
            count = increment_attack()
            result_label.config(text=f"⚠️ SQL Injection Detected! ({confidence:.2f}% confident)", fg="red")
            counter_label.config(text="Total Attacks Detected: " + str(count))

            with open("attack_log.txt", "a") as log:
                log.write(query + "\n")
        else:
            result_label.config(text=f"✅ Query looks safe ({confidence:.2f}% confident)", fg="green")

    def show_logs():
        log_window = tk.Toplevel(root)
        log_window.title("Attack Logs")
        log_window.geometry("400x300")
        text_area = tk.Text(log_window)
        text_area.pack(fill="both", expand=True)

        try:
            with open("attack_log.txt", "r") as file:
                logs = file.read()
                text_area.insert(tk.END, logs)
        except FileNotFoundError:
            text_area.insert(tk.END, "No attack logs found.")

    root = tk.Tk()
    root.title("SQL Injection Detector")
    root.geometry("450x320")

    tk.Label(root, text="Enter SQL Query").pack()
    entry = tk.Entry(root, width=55)
    entry.pack(pady=10)

    tk.Button(root, text="Check Query", command=gui_detect).pack()
    tk.Button(root, text="View Attack Logs", command=show_logs).pack(pady=5)

    result_label = tk.Label(root, text="")
    result_label.pack(pady=10)

    counter_label = tk.Label(root, text="Total Attacks Detected: 0")
    counter_label.pack(pady=10)

    root.mainloop()

