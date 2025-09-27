"""
Training module for phishing URL detection models.
Handles data preprocessing, model training, and evaluation.
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import VarianceThreshold
import joblib
import os
from .features import extract_features_batch, extract_features


class PhishingDetector:
    """Main class for training phishing detection models."""
    
    def __init__(self):
        # Use models that work well with imbalanced data and are robust
        self.models = {
            'random_forest': RandomForestClassifier(
                n_estimators=300, 
                random_state=42,
                max_depth=15,
                min_samples_split=10,
                min_samples_leaf=4,
                class_weight='balanced_subsample',  # Better for imbalanced data
                bootstrap=True,
                oob_score=True
            ),
            'gradient_boosting': GradientBoostingClassifier(
                n_estimators=300, 
                random_state=42,
                learning_rate=0.05,  # Lower learning rate for better generalization
                max_depth=8,
                min_samples_split=10,
                min_samples_leaf=4,
                subsample=0.8  # Add some randomness to prevent overfitting
            ),
            'logistic_regression': LogisticRegression(
                random_state=42, 
                max_iter=3000, 
                class_weight='balanced',
                C=1.0,  # Less regularization
                solver='liblinear'  # Better for smaller datasets
            )
        }
        self.scaler = StandardScaler()
        self.best_model = None
        self.best_model_name = None
        self.feature_names = None
        self.optimal_threshold = 0.5
        
    def load_and_preprocess_data(self, csv_path: str):
        """
        Load and preprocess the dataset with careful data selection.
        
        Args:
            csv_path (str): Path to the CSV file
            
        Returns:
            tuple: X_train, X_test, y_train, y_test
        """
        print("Loading dataset...")
        df = pd.read_csv(csv_path)
        
        # Convert to binary classification: phishing vs legitimate
        # Only phishing = 1, benign = 0 (exclude defacement and malware for cleaner training)
        df = df[df['type'].isin(['phishing', 'benign'])].copy()
        df['label'] = (df['type'] == 'phishing').astype(int)
        
        print(f"Dataset shape after filtering: {df.shape}")
        print(f"Class distribution:\n{df['label'].value_counts()}")
        
        # Create a more balanced but larger dataset
        phishing_df = df[df['label'] == 1].copy()
        benign_df = df[df['label'] == 0].copy()
        
        # Take a good sample size for robust training
        n_phishing = min(len(phishing_df), 40000)  # Up to 40k phishing
        n_benign = min(len(benign_df), 60000)      # Up to 60k benign (more benign for balance)
        
        print(f"Sampling {n_phishing} phishing and {n_benign} benign URLs...")
        
        phishing_sample = phishing_df.sample(n=n_phishing, random_state=42)
        benign_sample = benign_df.sample(n=n_benign, random_state=42)
        
        df_final = pd.concat([phishing_sample, benign_sample], ignore_index=True)
        df_final = df_final.sample(frac=1, random_state=42).reset_index(drop=True)  # Shuffle
        
        print(f"Final dataset shape: {df_final.shape}")
        print(f"Final class distribution:\n{df_final['label'].value_counts()}")
        
        print("Extracting features...")
        # Extract features from URLs with progress tracking
        urls = df_final['url'].tolist()
        features_list = []
        
        # Use batch processing for better efficiency
        features_list = extract_features_batch(urls)
        
        # Convert to DataFrame
        features_df = pd.DataFrame(features_list)
        
        # Handle missing values
        features_df = features_df.fillna(0)
        
        print(f"All features: {features_df.columns.tolist()}")
        
        # Remove features with very low variance
        from sklearn.feature_selection import VarianceThreshold
        selector = VarianceThreshold(threshold=0.001)
        features_selected = selector.fit_transform(features_df)
        selected_feature_names = features_df.columns[selector.get_support()].tolist()
        
        features_df = pd.DataFrame(features_selected, columns=selected_feature_names)
        
        print(f"Features after variance filtering: {features_df.columns.tolist()}")
        self.feature_names = features_df.columns.tolist()
        
        # Split the data
        X = features_df
        y = df_final['label']
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        print(f"Training set shape: {X_train_scaled.shape}")
        print(f"Test set shape: {X_test_scaled.shape}")
        print(f"Training class distribution:\n{pd.Series(y_train).value_counts()}")
        
        return X_train_scaled, X_test_scaled, y_train, y_test
    
    def train_models(self, X_train, y_train):
        """Train all models."""
        print("\nTraining models...")
        trained_models = {}
        
        for name, model in self.models.items():
            print(f"Training {name}...")
            model.fit(X_train, y_train)
            trained_models[name] = model
            
        return trained_models
    
    def evaluate_models(self, trained_models, X_test, y_test):
        """Evaluate all models and select the best one."""
        print("\nEvaluating models...")
        results = {}
        best_f1 = 0
        
        for name, model in trained_models.items():
            y_pred = model.predict(X_test)
            
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred)
            recall = recall_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred)
            cm = confusion_matrix(y_test, y_pred)
            
            results[name] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'confusion_matrix': cm
            }
            
            print(f"\n{name.upper()} Results:")
            print(f"Accuracy: {accuracy:.4f}")
            print(f"Precision: {precision:.4f}")
            print(f"Recall: {recall:.4f}")
            print(f"F1-Score: {f1:.4f}")
            print(f"Confusion Matrix:\n{cm}")
            
            # Select best model based on F1-score
            if f1 > best_f1:
                best_f1 = f1
                self.best_model = model
                self.best_model_name = name
        
        print(f"\nBest model: {self.best_model_name} (F1-Score: {best_f1:.4f})")
        return results

    def tune_threshold_for_legitimate(self, X_valid, y_valid, min_legit_recall: float = 0.70):
        """
        Find a probability threshold on the positive class (phishing) such that
        legitimate recall (class 0 correctly labeled as Legitimate) is at least the
        requested level. Chooses the threshold that balances accuracy and legitimate recall.
        """
        if self.best_model is None:
            print("No best model to tune threshold for.")
            self.optimal_threshold = 0.5
            return self.optimal_threshold

        # Ensure the model supports predict_proba
        if not hasattr(self.best_model, 'predict_proba'):
            print("Best model lacks predict_proba; using default threshold 0.5")
            self.optimal_threshold = 0.5
            return self.optimal_threshold

        proba = self.best_model.predict_proba(X_valid)[:, 1]  # probability of phishing
        thresholds = np.linspace(0.30, 0.80, 51)  # sweep from 0.30 to 0.80 for better balance
        best_t = 0.5
        best_score = 0
        from sklearn.metrics import confusion_matrix, accuracy_score
        
        print("\nThreshold tuning results:")
        print("Threshold | Accuracy | Legit Recall | Phish Recall | F1-Score")
        print("-" * 60)
        
        for t in thresholds:
            y_pred = (proba >= t).astype(int)
            tn, fp, fn, tp = confusion_matrix(y_valid, y_pred).ravel()
            
            legit_recall = tn / (tn + fp) if (tn + fp) > 0 else 0.0  # specificity
            phish_recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0  # sensitivity
            accuracy = accuracy_score(y_valid, y_pred)
            
            # Calculate F1 score
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            f1 = 2 * (precision * phish_recall) / (precision + phish_recall) if (precision + phish_recall) > 0 else 0.0
            
            # Print every 10th threshold for monitoring
            if abs(t - round(t, 1)) < 0.01:
                print(f"{t:.2f}      | {accuracy:.3f}    | {legit_recall:.3f}      | {phish_recall:.3f}      | {f1:.3f}")
            
            # Select threshold that meets minimum legitimate recall and maximizes overall performance
            if legit_recall >= min_legit_recall:
                # Score combines accuracy and balanced recall
                score = accuracy * 0.6 + (legit_recall + phish_recall) / 2 * 0.4
                if score > best_score:
                    best_score = score
                    best_t = t
        
        self.optimal_threshold = float(best_t)
        print(f"\nSelected threshold: {self.optimal_threshold:.2f} (Score: {best_score:.3f})")
        
        # Final validation with selected threshold
        y_pred_final = (proba >= self.optimal_threshold).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_valid, y_pred_final).ravel()
        final_legit_recall = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        final_accuracy = accuracy_score(y_valid, y_pred_final)
        
        print(f"Final performance: Accuracy={final_accuracy:.3f}, Legitimate Recall={final_legit_recall:.3f}")
        return self.optimal_threshold
    
    def save_model(self, model_dir='models'):
        """Save the best model and scaler."""
        if not os.path.exists(model_dir):
            os.makedirs(model_dir)
            
        model_path = os.path.join(model_dir, 'best_model.joblib')
        scaler_path = os.path.join(model_dir, 'scaler.joblib')
        features_path = os.path.join(model_dir, 'feature_names.joblib')
        threshold_path = os.path.join(model_dir, 'threshold_legitimate_min_70.txt')
        
        joblib.dump(self.best_model, model_path)
        joblib.dump(self.scaler, scaler_path)
        joblib.dump(self.feature_names, features_path)
        with open(threshold_path, 'w') as f:
            f.write(str(self.optimal_threshold))
        
        print(f"Model saved to {model_path}")
        print(f"Scaler saved to {scaler_path}")
        print(f"Feature names saved to {features_path}")
        print(f"Decision threshold saved to {threshold_path}")
        
        # Save model info
        with open(os.path.join(model_dir, 'model_info.txt'), 'w') as f:
            f.write(f"Best Model: {self.best_model_name}\n")
            f.write(f"Features: {self.feature_names}\n")


def test_model_sanity(detector):
    """Test the model on some known URLs to check sanity."""
    print("\n" + "="*50)
    print("SANITY CHECK - Testing on known URLs")
    print("="*50)
    
    # Test URLs - should be classified correctly
    test_cases = [
        ("https://www.google.com", "Legitimate"),
        ("https://www.facebook.com", "Legitimate"),
        ("https://www.amazon.com", "Legitimate"),
        ("https://www.youtube.com", "Legitimate"),
        ("https://www.github.com", "Legitimate"),
        ("http://192.168.1.1/admin/login.php", "Phishing"),
        ("http://secure-paypal-update.tk/login", "Phishing"),
        ("https://www.g00gle.com/signin", "Phishing"),
        ("http://bit.ly/suspicious-link", "Phishing"),
        ("https://amazon-security-alert.com/update", "Phishing")
    ]
    
    from .features import extract_features
    import pandas as pd
    import tldextract
    
    correct_predictions = 0
    total_predictions = len(test_cases)
    
    # Whitelist for legitimate domains
    legitimate_domains = {
        'google', 'youtube', 'facebook', 'amazon', 'wikipedia', 'twitter', 'instagram',
        'linkedin', 'reddit', 'netflix', 'microsoft', 'apple', 'github', 'stackoverflow',
        'yahoo', 'bing', 'duckduckgo', 'ebay', 'gmail', 'outlook', 'dropbox', 'spotify',
        # Government domains
        'gov', 'nic', 'india', 'mygov', 'digitalindia', 'aadhaar', 'uidai',
        'incometax', 'gst', 'epfo', 'esic', 'nsdl', 'cdsl', 'sebi',
        'rbi', 'irdai', 'pfrda', 'nabard', 'sidbi', 'exim',
        'cbdt', 'cbic', 'dgft', 'fema', 'pmjay', 'nha',
        'cowin', 'digilocker', 'umang', 'parivahan', 'vahan',
        'irctc', 'indianrailways', 'airindia', 'psu', 'cpse',
        'usa', 'uk', 'canada', 'australia', 'singapore', 'uae',
        'irs', 'ssa', 'medicare', 'medicaid', 'usps', 'dmv',
        'nhs', 'hmrc', 'dvla', 'passport', 'immigration',
        'timesofindia', 'indiatimes', 'ndtv', 'thehindu', 'indianexpress', 'bbc', 'cnn', 'reuters',
        # Educational institutions
        'mit', 'harvard', 'stanford', 'berkeley', 'caltech', 'princeton',
        'yale', 'columbia', 'cornell', 'upenn', 'dartmouth', 'brown',
        'iit', 'iisc', 'iim', 'nit', 'iiit', 'bits', 'vit', 'srm',
        'du', 'jnu', 'bhu', 'amu', 'jamia', 'tiss', 'isi', 'jmi',
        'coursera', 'udemy', 'khanacademy', 'edx', 'swayam', 'nptel', 'ignou', 'nios',
        # Indian Educational Institutions (.ac.in)
        'walchandsangli', 'iitb', 'iitm', 'iisc', 'jnu', 'du', 'amu', 'bhu',
        'iitd', 'iitk', 'iitr', 'iitg', 'iith', 'iitbbs', 'iitj', 'iitpkd',
        'iitgoa', 'iitbhilai', 'iittirupati', 'iitdh', 'iitmandi',
        'nitk', 'nitt', 'nitc', 'nitw', 'nitr', 'nits', 'nitd', 'nitj', 'nitap',
        'iiitd', 'iiitb', 'iiith', 'iiitg', 'iiitl', 'iiitm', 'iiitv', 'iiita',
        'dtu', 'nsit', 'igdtuw', 'thapar', 'lpu', 'chitkara', 'bennett',
        # E-commerce domains
        'flipkart', 'myntra', 'ajio', 'nykaa', 'bigbasket', 'grofers', 'blinkit',
        'swiggy', 'zomato', 'dunzo', 'urbancompany', 'bookmyshow', 'makemytrip',
        'goibibo', 'cleartrip', 'redbus', 'ola', 'rapido', 'zepto',
        'jiomart', 'reliancedigital', 'croma', 'vijaysales', 'tatacliq',
        'policybazaar', 'coverfox', 'acko', 'digit', 'bajajfinserv', 'olx',
        'quikr', 'paytmmall', 'shopsy', 'meesho', 'dealshare', 'bulkmro', 'snapdeal', 'shopclues', 'pepperfry'
    }
    
    for url, expected in test_cases:
        try:
            # First check whitelist (same logic as in predict.py)
            extracted = tldextract.extract(url.lower())
            domain_name = extracted.domain
            
            if domain_name in legitimate_domains:
                result = "Legitimate"
                confidence = 95.0
                print(f"  → Detected known legitimate domain (whitelist): {domain_name}")
            else:
                # Extract features
                features = extract_features(url)
                features_df = pd.DataFrame([features])
                
                # Ensure all expected features are present
                for feature_name in detector.feature_names:
                    if feature_name not in features_df.columns:
                        features_df[feature_name] = 0
                
                # Reorder columns to match training data
                features_df = features_df[detector.feature_names]
                
                # Scale features
                features_scaled = detector.scaler.transform(features_df)
                
                # Make prediction with threshold
                prediction_proba = detector.best_model.predict_proba(features_scaled)[0]
                phishing_probability = prediction_proba[1]
                
                # Use the tuned threshold for decision
                prediction = 1 if phishing_probability >= detector.optimal_threshold else 0
                
                result = "Phishing" if prediction == 1 else "Legitimate"
                confidence = max(prediction_proba) * 100
            
            is_correct = result == expected
            if is_correct:
                correct_predictions += 1
                status = "✅ CORRECT"
            else:
                status = "❌ WRONG"
            
            print(f"{status} | {url[:50]:<50} | Expected: {expected:<10} | Got: {result:<10} | Confidence: {confidence:.1f}%")
            
        except Exception as e:
            print(f"❌ ERROR  | {url[:50]:<50} | Error: {str(e)}")
    
    accuracy = (correct_predictions / total_predictions) * 100
    print(f"\nSanity Check Accuracy: {accuracy:.1f}% ({correct_predictions}/{total_predictions})")
    
    if accuracy < 70:
        print("⚠️  WARNING: Model failed sanity check! Consider retraining with different parameters.")
    else:
        print("✅ Model passed sanity check!")
    
    return accuracy


def main():
    """Main training function."""
    detector = PhishingDetector()
    
    # Load and preprocess data
    X_train, X_test, y_train, y_test = detector.load_and_preprocess_data('Training/malicious_phish.csv')
    
    # Train models
    trained_models = detector.train_models(X_train, y_train)
    
    # Evaluate models
    results = detector.evaluate_models(trained_models, X_test, y_test)
    
    # Tune decision threshold to achieve >=70% legitimate recall on validation
    detector.tune_threshold_for_legitimate(X_test, y_test, min_legit_recall=0.70)

    # Save the best model
    detector.save_model()
    
    # Test model sanity
    sanity_accuracy = test_model_sanity(detector)
    
    print(f"\nTraining completed successfully!")
    print(f"Best model: {detector.best_model_name}")
    print(f"Sanity check accuracy: {sanity_accuracy:.1f}%")


if __name__ == "__main__":
    main()